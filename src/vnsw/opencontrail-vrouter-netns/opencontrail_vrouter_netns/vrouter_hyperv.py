import os
import time
import sys
import argparse
import subprocess
import uuid

import netaddr
import requests
import json
import paramiko
import socket

from common import validate_uuid


def powershell(cmds):
    powershell_command = subprocess.list2cmdline(cmds)
    process_cmdline = ["powershell.exe", "-NonInteractive", "-Command"]
    process_cmdline.append(powershell_command)
    try:
        output = subprocess.check_output(process_cmdline, shell=True)
    except subprocess.CalledProcessError:
        raise
    return output


class HyperVManager(object):
    NAME_LEN = 14
    WINGW_PREFIX = 'contrail-wingw-'
    LEFT_DEV_PREFIX = 'eth'
    RIGHT_DEV_PREFIX = 'eth'
    PORT_TYPE = 'NameSpacePort'
    BASE_URL = "http://localhost:9091/port"
    HEADERS = {'content-type': 'application/json'}

    HYPERV_GENERATION = '2'
    RAM_GB = '1GB'

    USERNAME = 'ubuntu'
    PASSWORD = 'ubuntu'

    INJECT_IP_SCRIPT_REL_PATH = "vrouter_hyperv_inject_ip.ps1"
    WAIT_FOR_VM_TIME_SEC = 5
    NUM_INJECT_RETRIES = 5

    HOST_MGMT_IP = "169.254.150.1"
    MGMT_PREFIX_LEN = 16
    MGMT_IP_RANGE = netaddr.IPRange("169.254.150.10", "169.254.150.254")
    MGMT_SUBNET_MASK = "255.255.0.0"

    def __init__(self, vm_uuid, nic_left, nic_right, wingw_vm_name=None,
                 vm_location=None, vhd_path=None,
                 mgmt_vswitch_name=None, vrouter_vswitch_name=None,
                 gw_ip=None):

        self.vm_uuid = vm_uuid
        self.nic_left = nic_left
        self.nic_right = nic_right
        self.gw_ip = gw_ip

        self.vm_location = vm_location
        self.vhd_path = vhd_path
        self.mgmt_vswitch_name = mgmt_vswitch_name
        self.vrouter_vswitch_name = vrouter_vswitch_name

        self.wingw_name = self.WINGW_PREFIX + self.vm_uuid \
            if wingw_vm_name is None else wingw_vm_name

        self.nic_left['name'] = (self.LEFT_DEV_PREFIX + "1")
                                #self.nic_left['uuid'])[:self.NAME_LEN]
        self.nic_right['name'] = (self.RIGHT_DEV_PREFIX + "2")
                                #self.nic_right['uuid'])[:self.NAME_LEN]


    def spawn_vm(self):
        """calls powershell to spawn vm """
        if self._vm_exists():
            raise ValueError("Specified Windows gateway VM already exists")

        self._configure_host_mgmt_ip()

        powershell(["New-VM", "-Name", self.wingw_name, \
                    "-Path", self.vm_location, \
                    "-Generation", self.HYPERV_GENERATION, \
                    "-MemoryStartupBytes", self.RAM_GB, \
                    "-VHDPath", self.vhd_path, \
                    "-SwitchName", self.mgmt_vswitch_name])

        powershell(["Set-VMFirmware", "-VMName", self.wingw_name, \
                    "-EnableSecureBoot", "Off"])

        powershell(["Start-VM", "-Name", self.wingw_name])

        self.new_mgmt_ip = self._generate_new_mgmt_ip()
        self._configure_vm_mgmt_ip()

        powershell(["Add-VMNetworkAdapter", "-VMName", self.wingw_name,
                    "-SwitchName", self.vrouter_vswitch_name,
                    "-Name", self.nic_left['win_name']])
        powershell(["Add-VMNetworkAdapter", "-VMName", self.wingw_name,
                    "-SwitchName", self.vrouter_vswitch_name,
                    "-Name", self.nic_right['win_name']])


    def destroy_vm(self):
        """calls powershell to destroy vm"""
        if not self._vm_exists():
            raise ValueError("Specified Windows gateway VM does not exist")
        powershell(["Stop-VM", "-Name", self.wingw_name, "-Force"])
        powershell(["Remove-VM", "-Name", self.wingw_name, "-Force"])


    def set_snat(self):
        """sshs into gateway machine and configures SNAT"""
        self.ssh_client = None
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy())
            self._connect_with_retries()
            self._setup_snat()
        finally:
            if self.ssh_client:
                self.ssh_client.close()


    def register_to_agent(self):
        """registers wingw interface (as seen on host) to agent"""
        # get 2 snat ifaces of wingw VM
        # _add_port_to_agent on those nics
        # TODO do we have to register mgmt interface?
        pass


    def unregister_from_agent(self):
        """unregisters wingw interfaces (as seen on host) from agent"""
        # self._delete_port_from_agent(self.nic_left)
        # self._delete_port_from_agent(self.nic_right)
        # TODO do we have to unregister mgmt interface?
        pass


    def _vm_exists(self):
        """calls powershell to check whether vm exists"""
        try:
            powershell(["Get-VM", "-Name", self.wingw_name])
        except subprocess.CalledProcessError as e:
            print e.returncode
            if e.returncode != 0:
                # vm doesn't exist
                return False
            else:
                # other exception
                raise
        return True


    def _configure_host_mgmt_ip(self):
        """configures host management adapter and its IP"""

        adapter_name = self.mgmt_vswitch_name
        current_ip = powershell(["Get-NetAdapter", "|",
                                 "Where-Object", "Name", "-Match", adapter_name, "|"
                                 "Get-NetIPAddress", "|",
                                 "Where-Object", "AddressFamily", "-eq", "IPv4", "|",
                                 "Select", "-ExpandProperty", "IPAddress"])
        if current_ip != self.HOST_MGMT_IP:
            if_index = powershell(["Get-NetAdapter", "|",
                                   "Where-Object", "Name", "-Match", adapter_name, "|"
                                   "Select", "-ExpandProperty", "ifIndex"])
            if current_ip != "":
                powershell(["Get-NetAdapter", "|",
                            "Where-Object", "Name", "-Match", adapter_name, "|"
                            "Remove-NetIPAddress", "-Confirm:$false"])
            powershell(["New-NetIPAddress", "-IPAddress", self.HOST_MGMT_IP,
                        "-PrefixLength", str(self.MGMT_PREFIX_LEN),
                        "-InterfaceIndex", if_index])


    def _generate_new_mgmt_ip(self):
        """generates an IP to give to new gateway VM"""
        used_ips = self._get_all_mgmt_ips()

        used_ips = netaddr.IPSet(used_ips)
        pool_ips = netaddr.IPSet(self.MGMT_IP_RANGE)
        free_ips = pool_ips ^ used_ips

        try:
            first_available_ip = next(iter(free_ips))
        except StopIteration:
            raise ValueError("Ran out of management IPs for gateway VM")
        return first_available_ip


    def _get_mgmt_ip(self):
        """queries hyper-v for management IP of SNAT VM"""
        return self._get_mgmt_ips_of(self.wingw_name)


    def _get_all_mgmt_ips(self):
        """queries hyper-v for management IPs of all SNAT VMs"""
        try:
            mgmt_ips = self._get_mgmt_ips_of(self.WINGW_PREFIX + "*")
        except IndexError:
            # ignore, just return an empty list
            mgmt_ips = []
        return mgmt_ips


    def _get_mgmt_ips_of(self, vmname_with_wildcard):
        ips = powershell(["Get-VMNetworkAdapter", "-VMName", vmname_with_wildcard, "|",
                          "Where", "SwitchName", "-eq", self.mgmt_vswitch_name, "|",
                          "Select", "-ExpandProperty", "IPAddresses"])
        if ips == "":
            raise IndexError("no management IP found")
        ips = ips.splitlines()

        # if multiple IPs connected to mgmt switch, we can use either one
        return ips[0]


    def _configure_vm_mgmt_ip(self):
        this_script_path = os.path.realpath(__file__)
        this_script_dir = os.path.dirname(this_script_path)
        inject_ip_script_path = os.path.join(this_script_dir,
                                             self.INJECT_IP_SCRIPT_REL_PATH)
        retry_num = 0
        while True:
            if retry_num == self.NUM_INJECT_RETRIES:
                raise RuntimeError("Waited for SNAT VM for too long")

            time.sleep(self.WAIT_FOR_VM_TIME_SEC)
            retry_num += 1
            try:
                powershell([inject_ip_script_path,
                            "-Name", self.wingw_name,
                            "-IPAddress", str(self.new_mgmt_ip),
                            "-Subnet", self.MGMT_SUBNET_MASK])
                powershell(["ping", str(self.new_mgmt_ip), "-n", "1"])
            except subprocess.CalledProcessError:
                continue
            else:
                break


    def _request_to_agent(self, url, method, data):
        method = getattr(requests, method)
        resp = method(url, data=data, headers=self.HEADERS)
        if resp.status_code != requests.codes.ok:
            error_str = resp.text
            try:
                err = json.loads(resp.text)
                error_str = err['error']
            except Exception:
                pass
            raise ValueError(error_str)


    def _add_port_to_agent(self, nic, display_name=None):
        if self.PORT_TYPE == "NovaVMPort":
            port_type_value = 0
        elif self.PORT_TYPE == "NameSpacePort":
            port_type_value = 1
        payload = {"ip-address": str(nic['ip'].ip), "tx-vlan-id": -1,
                   "display-name": display_name, "id": nic['uuid'],
                   "instance-id": self.vm_uuid, "ip6-address": '',
                   "rx-vlan-id": -1,
                   "system-name": self._get_wingw_iface_name(nic['uuid']),
                   "vn-id": '', "vm-project-id": '',
                   "type": port_type_value, "mac-address": str(nic['mac'])}
        json_dump = json.dumps(payload)
        # TODO no agent - uncomment when it works
        #self._request_to_agent(self.BASE_URL, 'post', json_dump) 


    def _delete_port_from_agent(self, nic):
        url = self.BASE_URL + "/" + nic['uuid']
        # TODO no agent - uncomment when it works
        # self._request_to_agent(url, 'delete', None)


    def _get_wingw_iface_name(self, uuid_str):
        pass
        # TODO no agent - uncomment and fix when it works
        #return (self.TAP_PREFIX + uuid_str)[:self.DEV_NAME_LEN]


    def _connect_with_retries(self):
        attempts = 0
        while True:
            try:
                self.ssh_client.connect(str(self.new_mgmt_ip),
                                        username=self.USERNAME,
                                        password=self.PASSWORD,
                                        auth_timeout=5)
                break
            except socket.error:
                attempts += 1
                if attempts >= 5:
                    break
                else:
                    raise


    def _exec_ssh_command(self, command):
        _, stdout, _ = self.ssh_client.exec_command(command)
        return stdout.channel.recv_exit_status()


    def _setup_snat(self):
        self._exec_ssh_command("sudo sysctl -w net.ipv4.ip_forward=1")
        self._exec_ssh_command("sudo ip link set dev {} up"
                               .format(self.nic_left['name']))
        self._exec_ssh_command("sudo ip link set dev {} up"
                               .format(self.nic_right['name']))
        self._exec_ssh_command("sudo ip addr add dev {} 10.0.0.1/24".format(self.nic_left['name']))
        self._exec_ssh_command("sudo ip addr add dev {} {}/24".format(self.nic_right['name'], self.gw_ip))
        self._exec_ssh_command("sudo iptables -t nat -F")
        self._exec_ssh_command("sudo iptables -t nat -A POSTROUTING -o {} "
                               "-j MASQUERADE"
                               .format(self.nic_right['name']))
        self._exec_ssh_command("sudo iptables -A FORWARD -i {} -o {} -m state "
                               "--state RELATED,ESTABLISHED -j ACCEPT"
                               .format(self.nic_right['name'],
                                       self.nic_left['name']))
        self._exec_ssh_command("sudo iptables -A FORWARD -i {} -o {} -j ACCEPT"
                               .format(self.nic_left['name'],
                                       self.nic_right['name']))
        self._exec_ssh_command("sudo /etc/init.d/iptables-persistent save")


class VRouterHyperV(object):
    """
    Create or destroy a Hyper-V Gateway VM for NAT between two virtual 
    networks.
    """

    def __init__(self):
        self._parse_args(sys.argv[1:])

    def _parse_args(self, args):
        """Return an argparse.ArgumentParser for me"""
        conf_parser = argparse.ArgumentParser(add_help=False)

        _, remaining_argv = conf_parser.parse_known_args(args)
        # Override with CLI options
        # Don't surpress add_help here so it will handle -h
        parser = argparse.ArgumentParser(
            # Inherit options from config_parser
            parents=[conf_parser],
            # print script description with -h/--help
            description=__doc__,
            # Don't mess with format of description
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparsers = parser.add_subparsers()

        create_parser = subparsers.add_parser('create')
        create_parser.add_argument(
            "--vm_location",
            required=True,
            help="Location of gateway VM")
        create_parser.add_argument(
            "--vhd_path",
            required=True,
            help="Path of VHD of VM")
        create_parser.add_argument(
            "--mgmt_vswitch_name",
            required=True,
            help="Name of management virtual switch")
        create_parser.add_argument(
            "--vrouter_vswitch_name",
            required=True,
            help="Name of vRouter virtual switch")
        create_parser.add_argument(
            "vm_id",
            help="Virtual machine UUID")
        create_parser.add_argument(
            "vmi_left_id",
            help="Left virtual machine interface UUID")
        create_parser.add_argument(
            "vmi_right_id",
            help="Right virtual machine interface UUID")
        create_parser.add_argument(
            "--vmi-left-mac",
            default=None,
            help=("Left virtual machine interface MAC. Default: automatically "
                  "generated by the system"))
        create_parser.add_argument(
            "--vmi-left-ip",
            default=None,
            help=("Left virtual machine interface IPv4 and mask "
                  "(ie: a.a.a.a/bb). Default mask to /32"))
        create_parser.add_argument(
            "--vmi-right-mac",
            default=None,
            help=("Right virtual machine interface MAC. Default: "
                  "automatically generated by the system"))
        create_parser.add_argument(
            "--vmi-right-ip",
            default=None,
            help=("Right virtual machine interface IPv4 and mask "
                  "(ie: a.a.a.a/bb). Default mask to /32"))
        create_parser.add_argument(
            "--gw-ip",
            default=None,
            help=("Gateway IP for Virtual Network"))
        create_parser.set_defaults(func=self.create)

        destroy_parser = subparsers.add_parser('destroy')
        destroy_parser.add_argument(
            "vm_id",
            help="Virtual machine UUID")
        destroy_parser.add_argument(
            "vmi_left_id",
            help="Left virtual machine interface UUID")
        destroy_parser.add_argument(
            "vmi_right_id",
            help="Right virtual machine interface UUID")
        destroy_parser.set_defaults(func=self.destroy)

        self.args = parser.parse_args(remaining_argv)

    def create(self):
        vm_id = validate_uuid(self.args.vm_id)

        nic_left = {}
        if uuid.UUID(self.args.vmi_left_id):
            nic_left['uuid'] = validate_uuid(self.args.vmi_left_id)
            nic_left['win_name'] = "int-{}".format(nic_left['uuid'])
            if self.args.vmi_left_mac:
                nic_left['mac'] = netaddr.EUI(self.args.vmi_left_mac,
                                              dialect=netaddr.mac_eui48)
            else:
                nic_left['mac'] = None
            if self.args.vmi_left_ip:
                nic_left['ip'] = netaddr.IPNetwork(self.args.vmi_left_ip)
            else:
                nic_left['ip'] = None

        nic_right = {}
        if uuid.UUID(self.args.vmi_right_id):
            nic_right['uuid'] = validate_uuid(self.args.vmi_right_id)
            nic_right['win_name'] = "gw-{}".format(nic_right['uuid'])
            if self.args.vmi_right_mac:
                nic_right['mac'] = netaddr.EUI(self.args.vmi_right_mac,
                                               dialect=netaddr.mac_eui48)
            else:
                nic_right['mac'] = None
            if self.args.vmi_right_ip:
                nic_right['ip'] = netaddr.IPNetwork(self.args.vmi_right_ip)
            else:
                nic_right['ip'] = None

        hv_mgr = HyperVManager(vm_id, nic_left, nic_right,
                               gw_ip=self.args.gw_ip,
                               vm_location=self.args.vm_location,
                               vhd_path=self.args.vhd_path,
                               mgmt_vswitch_name=self.args.mgmt_vswitch_name,
                               vrouter_vswitch_name=\
                                    self.args.vrouter_vswitch_name)
        hv_mgr.spawn_vm()
        hv_mgr.set_snat()
        hv_mgr.register_to_agent()


    def destroy(self):
        vm_id = validate_uuid(self.args.vm_id)
        nic_left = {}
        if uuid.UUID(self.args.vmi_left_id):
            nic_left = {'uuid': validate_uuid(self.args.vmi_left_id)}
        nic_right = {}
        if uuid.UUID(self.args.vmi_right_id):
            nic_right = {'uuid': validate_uuid(self.args.vmi_right_id)}

        hyperv_mgr = HyperVManager(vm_id, nic_left, nic_right)

        hyperv_mgr.unregister_from_agent()
        hyperv_mgr.destroy_vm()


def main():
    vrouter_hyperv = VRouterHyperV()
    vrouter_hyperv.args.func()


if __name__ == "__main__":
    main()

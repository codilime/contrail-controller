import argparse
import netaddr # pip install this
import sys
import uuid
import requests # pip install this
import json
import subprocess
import paramiko


def validate_uuid(val):
    try:
        if str(uuid.UUID(val)) == val:
            return val
    except (TypeError, ValueError, AttributeError):
        raise ValueError('Invalid UUID format')


def powershell(cmds):
    cmds = ["powershell.exe", "-NonInteractive"] + cmds
    try:
        output = subprocess.check_output(cmds, shell=True)
        print output
    except subprocess.CalledProcessError as e:
        print e.output
        raise
    return output


class HyperVManager(object):
    SNAT_RT_TABLES_ID = 42
    NAME_LEN = 14
    WINGW_PREFIX = 'contrail-wingw-'
    LEFT_DEV_PREFIX = 'eth-'
    RIGHT_DEV_PREFIX = 'eth-'
    PORT_TYPE = 'NameSpacePort' # should maybe be NovaVMPort?
    BASE_URL = "http://localhost:9091/port"
    HEADERS = {'content-type': 'application/json'}

    HYPERV_GENERATION = '2'
    RAM_GB = '1GB'

    USERNAME = 'ubuntu'
    PASSWORD = 'ubuntu'

    WMI_VIRT_NAMESPACE = "root\\virtualization\\v2"

    MGMT_IP_RANGE = netaddr.IPRange("169.254.150.0", "169.254.200.0")

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

        self.nic_left['name'] = (self.LEFT_DEV_PREFIX +
                                 self.nic_left['uuid'])[:self.NAME_LEN]
        self.nic_right['name'] = (self.RIGHT_DEV_PREFIX +
                                  self.nic_right['uuid'])[:self.NAME_LEN]


    def spawn_vm(self):
        """calls powershell to spawn vm """
        if self._vm_exists():
            raise ValueError("Specified Windows gateway VM already exists")

        _ = powershell(["New-VM", "-Name", self.wingw_name, \
                        "-Path", self.vm_location, \
                        "-Generation", self.HYPERV_GENERATION, \
                        "-MemoryStartupBytes", self.RAM_GB, \
                        "-VHDPath", self.vhd_path, \
                        "-SwitchName", self.mgmt_vswitch_name])

        # TODO add two other NICs to self.vrouter_vswitch_name

        _ = powershell(["Set-VMFirmware", "-VMName", self.wingw_name, \
                        "-EnableSecureBoot", "Off"])

        _ = powershell(["Start-VM", "-Name", self.wingw_name])

        new_mgmt_ip = self._generate_new_mgmt_ip()
        #self._configure_vm_mgmt_ip(new_mgmt_ip)


    def destroy_vm(self):
        """calls powershell to destroy vm """
        if not self._vm_exists():
            raise ValueError("Specified Windows gateway VM does not exist")
        _ = powershell(["Stop-VM", "-Name", self.wingw_name, "-Force"])
        _ = powershell(["Remove-VM", "-Name", self.wingw_name, "-Force"])


    def set_snat(self):
        """sshs into gateway machine and configures SNAT"""
        # get mgmt IP of machine

        mgmt_ip = self._get_mgmt_ip()

        # ssh into machine

        ssh_client = None
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.connect(mgmt_ip, username=self.USERNAME,
                               password=self.PASSWORD)

            self._setup_snat(ssh_client)

        finally:
            if ssh_client:
                ssh_client.close()


    def register_to_agent(self):
        """registers wingw interface (as seen on host) to agent"""
        # get 2 snat ifaces of wingw VM
        # _add_port_to_agent on those nics
        # TODO do we have to register mgmt interface?
        pass


    def unregister_from_agent(self):
        """unregisters wingw interfaces (as seen on host) from agent"""
        self._delete_port_from_agent(self.nic_left)
        self._delete_port_from_agent(self.nic_right)
        # TODO do we have to unregister mgmt interface?
        pass


    def _vm_exists(self):
        """calls powershell to check whether vm exists"""
        try:
            _ = powershell(["Get-VM", "-Name", self.wingw_name])
        except subprocess.CalledProcessError as e:
            if "unable to find" in e.output:
                # vm doesn't exist
                return False
            else:
                # other exception
                raise
        return True


    def _generate_new_mgmt_ip(self):
        """generates an IP to give to new gateway VM"""
        used_ips = self._get_all_mgmt_ips()

        used_ips = netaddr.IPSet(used_ips)
        pool_ips = netaddr.IPSet(self.MGMT_IP_RANGE)
        free_ips = pool_ips ^ used_ips

        try:
            first_available_ip = next(ip for ip in free_ips)
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
        ips = powershell(["Get-VMNetworkAdapter -VMName {} | "
                          "Where SwitchName -eq {} | "
                          "Select -ExpandProperty IPAddresses"
                          .format(vmname_with_wildcard, self.mgmt_vswitch_name)])
        if ips == "":
            raise IndexError("no management IP found")
        ips = ips.splitlines()

        # if multiple IPs connected to mgmt switch, we can use either one
        return ips[0]


    def _configure_vm_mgmt_ip(self, ip_to_set):
        #
        # Required:
        # - self.wingw_name
        # - self.wingw_mgmt_adapter_name
        #
        wmi_client = wmi.WMI(namespace=WMI_VIRT_NAMESPACE)

        vms = wmi_client.Msvm_ComputerSystem()
        vm = [vm for vm in vms if vm.ElementName == self.wingw_name][0]

        vm_settings_ = vm.associators(wmi_result_class="Msvm_VirtualSystemSettingData")
        vm_settings = [sett for sett in vm_settings_ if sett.VirtualSystemType == "Microsoft:Hyper-V:System:Realized"]
        vm_settings = vm_settings[0]

        vm_adapters = vm_settings.associators(wmi_result_class="Msvm_SyntheticEthernetPortSettingData")
        vm_adapter = [adapter for adapter in vm_adapters if adapter.ElementName == self.wingw_mgmt_adapter_name]
        vm_adapter = vm_adapter[0]

        net_settings_ = vm_adapter.associators(wmi_result_class="Msvm_GuestNetworkAdapterConfiguration")
        net_settings = net_settings_[0]

        # TODO: decide on mgmt_subnet
        net_settings.IPAddresses = (self.ip_to_set,)
        net_settings.Subnets = (self.mgmt_subnet,)
        net_settings.DHCPEnabled = False
        net_settings.ProtocolIFType = 4096

        service_ = wmi_client.Msvm_VirtualSystemManagementService()
        service = service_[0]

        # TODO: net_settings parameter does not work
        # <x_wmi: Unexpected COM Error (-2147352567, 'Exception occurred.', (0, u'SWbemProperty', u'Type mismatch ', None, 0, -2147217403), None)>
        job, ret = service.SetGuestNetworkAdapterConfiguration(vm, net_settings)


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

        # TODO no agent - uncomment when works
        #self._request_to_agent(self.BASE_URL, 'post', json_dump) 


    def _delete_port_from_agent(self, nic):
        url = self.BASE_URL + "/" + nic['uuid']
        # TODO no agent - uncomment when works
        # self._request_to_agent(url, 'delete', None)


    def _get_wingw_iface_name(self, uuid_str):
        pass
        #return (self.TAP_PREFIX + uuid_str)[:self.DEV_NAME_LEN]


    def _setup_snat(self, ssh_client):
        ssh_client.exec_command("sysctl -w net.ipv4.ip_forward=1")
        ssh_client.exec_command("iptables -t nat -F")
        ssh_client.exec_command("iptables -t nat -A POSTROUTING -o {} "
                                "-j MASQUERADE"
                                .format(self.nic_right['name']))
        ssh_client.exec_command("iptables -A FORWARD -i {} -o {} -m state "
                                "--state RELATED,ESTABLISHED -j ACCEPT"
                                .format(self.nic_right['name'],
                                        self.nic_left['name']))
        ssh_client.exec_command("iptables -A FORWARD -i {} -o {} -j ACCEPT"
                                .format(self.nic_left['name'],
                                        self.nic_right['name']))


class VRouterHyperV(object):
    """Create or destroy a Hyper-V Gateway VM for NAT
    between two virtual networks.
    """

    def __init__(self, args_str=None):
        self.args = None
        if not args_str:
            args_str = ' '.join(sys.argv[1:])
        self._parse_args(args_str)

    def _parse_args(self, args_str):
        """Return an argparse.ArgumentParser for me"""
        conf_parser = argparse.ArgumentParser(add_help=False)

        _, remaining_argv = conf_parser.parse_known_args(args_str.split())
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
            if self.args.vmi_left_mac:
                nic_left['mac'] = netaddr.EUI(self.args.vmi_left_mac,
                                              dialect=netaddr.mac_eui48) # does eui48 break sth?
            else:
                nic_left['mac'] = None
            if self.args.vmi_left_ip:
                nic_left['ip'] = netaddr.IPNetwork(self.args.vmi_left_ip)
            else:
                nic_left['ip'] = None

        nic_right = {}
        if uuid.UUID(self.args.vmi_right_id):
            nic_right['uuid'] = validate_uuid(self.args.vmi_right_id)
            if self.args.vmi_right_mac:
                nic_right['mac'] = netaddr.EUI(self.args.vmi_right_mac,
                                               dialect=netaddr.mac_eui48) # does eui48 break sth?
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


        # if (self.args.update is False):
        #     if hyperv_mgr.is_netns_already_exists():
        #         # If the netns already exists, destroy it to be sure to set it
        #         # with new parameters like another external network
        #         if self.args.service_type == self.LOAD_BALANCER:
        #             hyperv_mgr.release_lbaas('create')
        #         hyperv_mgr.unplug_namespace_interface()
        #         hyperv_mgr.destroy()
        #     hyperv_mgr.create()

        # if self.args.service_type == self.SOURCE_NAT:
        #     netns_mgr.set_snat()
        # elif self.args.service_type == self.LOAD_BALANCER:
        #     if (netns_mgr.set_lbaas() == False):
        #         netns_mgr.destroy()
        #         msg = 'Falied to Launch LOADBALANCER'
        #         raise Exception(msg)
        # else:
        #     msg = ('The %s service type is not supported' %
        #            self.args.service_type)
        #     raise NotImplementedError(msg)

        # netns_mgr.plug_namespace_interface()

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

        # netns_mgr.unplug_namespace_interface()
        # if self.args.service_type == self.SOURCE_NAT:
        #     netns_mgr.destroy()
        # elif self.args.service_type == self.LOAD_BALANCER:
        #     netns_mgr.release_lbaas('destroy')
        #     netns_mgr.destroy()
        # else:
        #     msg = ('The %s service type is not supported' %
        #            self.args.service_type)
        #     raise NotImplementedError(msg)



def main(args_str=None):
    vrouter_hyperv = VRouterHyperV(args_str)
    vrouter_hyperv.args.func()


if __name__ == "__main__":
    main()

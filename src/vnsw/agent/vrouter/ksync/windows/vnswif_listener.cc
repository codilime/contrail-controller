/*
* Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
*/

#include <assert.h>

#include <bits/sockaddr.h>
//WINDOWSFIX - change to named pipes

#include <base/logging.h>
#include <base/util.h>
#include <cmn/agent_cmn.h>
#include <init/agent_param.h>
#include <cfg/cfg_init.h>
#include <oper/route_common.h>
#include <oper/mirror_table.h>
#include <ksync/ksync_index.h>
#include <vrouter/ksync/interface_ksync.h>
#include "vnswif_listener.h"

VnswInterfaceListenerWindows::VnswInterfaceListenerWindows(Agent *agent)
	: VnswInterfaceListenerBase(agent) {
	/* TODO(sodar): Implement */
}

VnswInterfaceListenerWindows::~VnswInterfaceListenerWindows() {
	/* TODO(sodar): Implement */
}

int VnswInterfaceListenerWindows::CreateSocket() {
	/* TODO(sodar): Implement */
	return 0;
}

void VnswInterfaceListenerWindows::SyncCurrentState() {
	/* TODO(sodar): Implement */
}

void VnswInterfaceListenerWindows::UpdateLinkLocalRoute(const Ip4Address &addr, bool del_rt) {
	/* TODO(sodar): Implement */
}

void VnswInterfaceListenerWindows::RegisterAsyncReadHandler() {
	/* TODO(sodar): Implement */
}

void VnswInterfaceListenerWindows::ReadHandler(const boost::system::error_code &, std::size_t length) {
	/* TODO(sodar): Implement */
}

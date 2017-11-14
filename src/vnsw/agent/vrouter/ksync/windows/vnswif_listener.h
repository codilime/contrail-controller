/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */

#ifndef windows_vnsw_agent_router_id_h
#define windows_vnsw_agent_router_id_h

#include <string>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>
#include "vrouter/ksync/vnswif_listener_base.h"

class VnswInterfaceListenerWindows : public VnswInterfaceListenerBase {
	DISALLOW_COPY_AND_ASSIGN(VnswInterfaceListenerWindows);
};

typedef VnswInterfaceListenerWindows VnswInterfaceListener;

#endif /* windows_vnsw_agent_router_id_h */

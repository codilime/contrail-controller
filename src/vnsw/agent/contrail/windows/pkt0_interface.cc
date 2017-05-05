/*
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */
 
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "base/logging.h"
#include "cmn/agent_cmn.h"
#include "init/agent_param.h"
#include "sandesh/sandesh_types.h"
#include "sandesh/sandesh.h"
#include "sandesh/sandesh_trace.h"
#include "pkt/pkt_types.h"
#include "pkt/pkt_init.h"
#include "../pkt0_interface.h"

#define TUN_INTF_CLONE_DEV "/dev/net/tun"
const LPCTSTR PKT0_PATH = TEXT("\\\\.\\vrouterPkt0");

#define TAP_TRACE(obj, ...)                                              \
do {                                                                     \
    Tap##obj::TraceMsg(PacketTraceBuf, __FILE__, __LINE__, __VA_ARGS__); \
} while (false)                                                          \

///////////////////////////////////////////////////////////////////////////////

void Pkt0Interface::InitControlInterface() {
    pkt_handler()->agent()->set_pkt_interface_name(name_);

    DWORD access_flags = GENERIC_READ | GENERIC_WRITE;
    DWORD attrs = OPEN_EXISTING;
    DWORD flags = FILE_FLAG_OVERLAPPED;

    HANDLE handle = CreateFile(PKT0_PATH, access_flags, 0, NULL, attrs, flags, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        LOG(ERROR, "Error while opening Pkt0 pipe: " << GetFormattedWindowsErrorMsg());
        assert(0);
    }

    boost::system::error_code ec;
    input_.assign(handle, ec);
    assert(ec == 0);

    VrouterControlInterface::InitControlInterface();
    AsyncRead();
}

void Pkt0RawInterface::InitControlInterface() {
   


}

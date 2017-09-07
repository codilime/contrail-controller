/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#endif

#include "base/test/addr_test_util.h"

namespace task_util {

InetVpnPrefix InetVpnPrefixIncrement(InetVpnPrefix prefix, int incr) {
    Ip4Address address = Ip4Address(prefix.addr().to_ulong() +
                                 (incr << (32 - prefix.prefixlen())));
    InetVpnPrefix result(prefix.route_distinguisher(), address,
                         prefix.prefixlen());
    return result;
}

Ip4Prefix Ip4PrefixIncrement(Ip4Prefix prefix, int incr) {
    Ip4Address address = Ip4Address(prefix.ip4_addr().to_ulong() +
                                 (incr << (32 - prefix.prefixlen())));
    Ip4Prefix result(address, prefix.prefixlen());

    return result;
}

}  // namespace task_util

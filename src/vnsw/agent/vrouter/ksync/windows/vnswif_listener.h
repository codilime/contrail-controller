/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#pragma once
//WINDOWSFIX - major change to use named pipes

#include <string>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/asio.hpp>
#include "vrouter/ksync/vnswif_listener_base.h"

//WINDOWS namespace local = boost::asio::local;

class VnswInterfaceListenerWindows : public VnswInterfaceListenerBase {

public:
	VnswInterfaceListenerWindows(Agent *agent);
	virtual ~VnswInterfaceListenerWindows();

private:


	int CreateSocket();
	virtual void SyncCurrentState();
	virtual void RegisterAsyncReadHandler();
	void ReadHandler(const boost::system::error_code &, std::size_t length);
	void UpdateLinkLocalRoute(const Ip4Address &addr, bool del_rt);

private:

	DISALLOW_COPY_AND_ASSIGN(VnswInterfaceListenerWindows);
};

typedef VnswInterfaceListenerWindows VnswInterfaceListener;



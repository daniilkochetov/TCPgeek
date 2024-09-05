/*
 *	LocalSubnets.cpp
 *
 *	Created on: Oct 12, 2023
 *	Last modified on: Oct 12, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/LocalSubnets.h"

std::vector<Subnet> LocalSubnets::m_localSubnets;

LocalSubnets::LocalSubnets() {
	std::stringstream s_stream(ProgramProperties::getLocalSubnetsStr());
	while(s_stream.good()) {
		std::string substr;
		getline(s_stream, substr, ',');
		Subnet* subnet = new Subnet(substr.c_str());
	    if (subnet->getPrefix() > 0 && subnet->getMask() > 0) {
	    	m_localSubnets.push_back(*subnet);
	    } else {
	    	throw std::runtime_error("Can't interpret a subnet in 'localSubnets' property");
	    }
	    delete(subnet);
	}
}

char LocalSubnets::getConnectionTopology(const in_addr s_addr, const in_addr c_addr) {
	// 'i' - Server is inside, client is outside
	// 'o' - Server is outside, client is inside
	// 'n' - Both neither inside, nor outside (when the traffic traverse the location with SPAN port)
	// 'b' - Server and client are inside
	bool isServerInside = isIpLocal(s_addr);
	bool isClientInside = isIpLocal(c_addr);
	if (isServerInside && !isClientInside) return 'i';
	if (!isServerInside && isClientInside) return 'o';
	if (!isServerInside && !isClientInside) return 'n';
	return 'b';
}


bool LocalSubnets::isIpLocal(const in_addr t_addr) {
	uint32_t size = m_localSubnets.size();
	for(unsigned int i = 0; i < size; i++) {
		if (m_localSubnets[i].isIpInSubnet(t_addr)) return true;
	}
	return false;
}

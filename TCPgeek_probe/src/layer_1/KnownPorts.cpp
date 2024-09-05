/*
 *	KnownPorts.cpp
 *
 *	Created on: Apr 27, 2023
 *	Last modified on: Apr 27, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/KnownPorts.h"

std::unordered_set<unsigned int> KnownPorts::m_knownPorts;

KnownPorts::KnownPorts() {
	std::stringstream s_stream(ProgramProperties::getServicePortsStr());
	log4cpp::Category& logRoot = log4cpp::Category::getRoot();

	while(s_stream.good()) {
		std::string substr;
		int iresult;

	    getline(s_stream, substr, ','); //get first string delimited by comma
	    try {
	    	iresult = stoi(substr, 0, 10);
	    	if (iresult > 0 && iresult < 65536) {
	    		KnownPorts::m_knownPorts.insert(iresult);
	    	}
	    } catch (...) {
	    	logRoot.warn("Can't interpret '%s' TCP port in 'servicePorts' property", substr.c_str());
	    }
	}
}

bool KnownPorts::isKnownPort(unsigned int t_port) {
	if (KnownPorts::m_knownPorts.find(t_port) != KnownPorts::m_knownPorts.end()) {
		return true;
	}
	return false;
}

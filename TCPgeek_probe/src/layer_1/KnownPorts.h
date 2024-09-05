/*
 *	KnownPorts.h
 *
 *	Created on: Apr 27, 2023
 *	Last modified on: Apr 27, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef KNOWNPORTS_H_
#define KNOWNPORTS_H_

#include <unordered_set>
#include <sstream>
#include <log4cpp/Category.hh> // for logging capabilities

#include "ProgramProperties.h"

class KnownPorts {
private:
	static std::unordered_set<unsigned int> m_knownPorts;
public:
	KnownPorts();
	static bool isKnownPort(unsigned int t_port);
};


#endif /* KNOWNPORTS_H_ */

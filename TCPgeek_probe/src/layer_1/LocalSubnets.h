/*
 *	LocalSubnets.h
 *
 *	Created on: Oct 12, 2023
 *	Last modified on: Oct 12, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef LOCALSUBNETS_H_
#define LOCALSUBNETS_H_

#include <vector>
#include <string>

#include "ProgramProperties.h"
#include "layer_1/Subnet.h"

class LocalSubnets {
private:
	static std::vector<Subnet> m_localSubnets;
	static bool isIpLocal(const in_addr t_addr);

public:
	LocalSubnets();
	static char getConnectionTopology(const in_addr s_addr, const in_addr c_addr);
};

#endif /* LOCALSUBNETS_H_ */

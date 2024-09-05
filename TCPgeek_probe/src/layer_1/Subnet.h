/*
 *	Subnet.h
 *
 *	Created on: Oct 9, 2023
 *	Last modified on: Oct 9, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef SUBNET_H_
#define SUBNET_H_

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

class Subnet {
private:
	u_int32_t m_prefix;
	u_int32_t m_mask;
	void trim(char * str);
public:
	Subnet(const char* t_localSubnetStr);
	bool isIpInSubnet(const in_addr addr);
	u_int32_t getMask() const;
	u_int32_t getPrefix() const;
};

#endif /* SUBNET_H_ */

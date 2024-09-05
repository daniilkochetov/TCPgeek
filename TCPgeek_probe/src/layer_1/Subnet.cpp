/*
 *	Subnet.cpp
 *
 *	Created on: Oct 9, 2023
 *	Last modified on: Oct 9, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/Subnet.h"

Subnet::Subnet(const char* t_localSubnetStr) {
	char *prefixStr = strdup(t_localSubnetStr);
	char *maskStr;
	struct in_addr addr;

	if (t_localSubnetStr != NULL) {
		strtok_r(prefixStr, "/", &maskStr);
		trim(prefixStr);
		trim(maskStr);
		if (inet_pton(AF_INET, prefixStr, &addr)) {
			m_prefix = ntohl(addr.s_addr);
		} else {
			m_prefix = 0;
		}
		m_mask = (u_int32_t) strtoul(maskStr, NULL, 10);
		m_mask = -1 << (32 - m_mask);
	} else {
		m_prefix = 0;
		m_mask = 0;
	}
	free(prefixStr);
}

bool Subnet::isIpInSubnet(const in_addr t_addr) {
	u_int32_t addrInt = ntohl(t_addr.s_addr);
	if (m_prefix ==  (addrInt & m_mask)) return true;
	else return false;
}

void Subnet::trim(char *str)
{
    int index, i;

    //Trim leading white spaces
    index = 0;
    while(str[index] == ' ' || str[index] == '\t' || str[index] == '\n') {
        index++;
    }
    //Shift all trailing characters to its left
    i = 0;
    while(str[i + index] != '\0') {
        str[i] = str[i + index];
        i++;
    }
    str[i] = '\0'; // Terminate string with NULL
    //Trim trailing white spaces
    i = 0;
    index = -1;
    while(str[i] != '\0') {
        if(str[i] != ' ' && str[i] != '\t' && str[i] != '\n') {
            index = i;
        }
        i++;
    }
    // Mark the next character to last non white space character as NULL
    str[index + 1] = '\0';
}

u_int32_t Subnet::getMask() const {
	return m_mask;
}

u_int32_t Subnet::getPrefix() const {
	return m_prefix;
}



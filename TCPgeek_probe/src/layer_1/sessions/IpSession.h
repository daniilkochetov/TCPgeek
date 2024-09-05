/*
 *	IpSession.h
 *
 *	Created on: Aug 10, 2023
 *	Last modified on: Aug 10, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef IPSESSION_H_
#define IPSESSION_H_

#include <stdint.h>

#include "layer_1/Packet.h"

class IpSession {
protected:
	//METRICS
	//total bytes in packet from pcap_pkthdr
	uint64_t m_totalBytes;

	//DIMENSIONS
	unsigned char m_ipProtocol;
public:
	IpSession();
	IpSession(const unsigned char t_ipProtocol);
	void update(const Packet* t_packet);

};

#endif /* IPSESSION_H_ */

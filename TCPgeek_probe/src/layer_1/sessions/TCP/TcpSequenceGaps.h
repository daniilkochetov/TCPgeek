/*
 *	TcpSequenceGaps.h
 *
 *	Created on: Mar 28, 2022
 *	Last modified on: Mar 28, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TcpSequenceGaps - is a list of TCP sequence gap records.
 *				Layer 2 - Analysis and logging of data structured at Layer 1
 */

#ifndef TCPSEQUENCEGAPS_H_
#define TCPSEQUENCEGAPS_H_


#include <list>
#include <stdio.h>
#include <inttypes.h>
#include <log4cpp/Category.hh>

#include "layer_1/sessions/TCP/TcpSequenceGap.h"

class TcpSequenceGaps {
private:
	std::list<TcpSequenceGap> m_tcpSequenceGapList;
public:
	//every TCP session object has a dynamically changing list of TCP sequence gaps
	TcpSequenceGaps();
	bool gapsContain(const uint32_t t_seqStart, const uint32_t t_seqEnd, TcpSequenceGap *t_gapFound, bool retransmit);
	//might be invoked only from the main thread of capturing
	//checks if the list of gaps contain seqStart...seqEnd fragment. If it does - updates the list accordingly and
	//returns gapFound if it does
	void addNewGap(const uint32_t t_seqStart, const uint32_t t_seqEnd);
	//might be invoked only from the main thread of capturing
	size_t size();
	void printGaps();
};

#endif /* TCPSEQUENCEGAPS_H_ */

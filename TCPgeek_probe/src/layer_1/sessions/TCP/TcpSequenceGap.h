/*
 *	TcpSequenceGap.h
 *
 *	Created on: Mar 28, 2022
 *	Last modified on: Mar 28, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TcpSequenceGap - Describes single gap in TCP session order.
 *				Layer 2 - Analysis and logging of data structured at Layer 1
 */

#ifndef TCPSEQUENCEGAP_H_
#define TCPSEQUENCEGAP_H_

#include <stdint.h>

class TcpSequenceGap {
private:
	uint32_t	m_seqGapStart;
	uint32_t	m_seqGapEnd;
public:
	TcpSequenceGap();
	TcpSequenceGap(const uint32_t t_seqGapStart, const uint32_t t_seqGapEnd);
	//defines a new node of std::list() of TCP sequence gaps that belongs to TCP session
	uint32_t getSeqGapEnd() const;
	uint32_t getSeqGapStart() const;
	void setSeqGapEnd(uint32_t t_seqGapEnd);
	void setSeqGapStart(uint32_t t_seqGapStart);

	TcpSequenceGap& operator = (const TcpSequenceGap other);
};

#endif /* TCPSEQUENCEGAP_H_ */

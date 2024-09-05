/*
 *	TcpSequenceGap.cpp
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


#include "layer_1/sessions/TCP/TcpSequenceGap.h"

TcpSequenceGap::TcpSequenceGap() {
	m_seqGapStart = 0;
	m_seqGapEnd = 0;
}

TcpSequenceGap::TcpSequenceGap(const uint32_t t_seqGapStart, const uint32_t t_seqGapEnd) {
	m_seqGapStart = t_seqGapStart;
	m_seqGapEnd = t_seqGapEnd;
}

TcpSequenceGap& TcpSequenceGap::operator = (const TcpSequenceGap other)
{
	m_seqGapStart = other.m_seqGapStart;
	m_seqGapEnd = other.m_seqGapEnd;
	return *this;
}

uint32_t TcpSequenceGap::getSeqGapEnd() const {
	return m_seqGapEnd;
}

void TcpSequenceGap::setSeqGapEnd(uint32_t t_seqGapEnd) {
	m_seqGapEnd = t_seqGapEnd;
}

void TcpSequenceGap::setSeqGapStart(uint32_t t_seqGapStart) {
	m_seqGapStart = t_seqGapStart;
}

uint32_t TcpSequenceGap::getSeqGapStart() const {
	return m_seqGapStart;
}

/*
 *	TcpSequenceGaps.cpp
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

#include "layer_1/sessions/TCP/TcpSequenceGaps.h"

TcpSequenceGaps::TcpSequenceGaps() {
	// TODO Auto-generated constructor stub

}

bool TcpSequenceGaps::gapsContain(const uint32_t t_seqStart, const uint32_t t_seqEnd, TcpSequenceGap *t_gapFound, bool retransmit) {
	uint32_t itSeqStart, itSeqEnd;

	if (t_seqStart > t_seqEnd) {
		if (t_seqStart - t_seqEnd > 1000000000) {
			//t_seqStart > t_seqEnd in case if we cycle over max uint32_t sequence number
			bool res1 = gapsContain(t_seqStart, UINT32_MAX, t_gapFound, retransmit);
			bool res2 = gapsContain(0, t_seqEnd, t_gapFound, retransmit);
			return res1 | res2;
		}
		return false;
	}

	bool result = false;
	retransmit = false;

	std::list<TcpSequenceGap>::iterator it = m_tcpSequenceGapList.begin();
	while (it != m_tcpSequenceGapList.end()) {
		itSeqStart = it->getSeqGapStart();
		itSeqEnd = it->getSeqGapEnd();
		if (itSeqStart == t_seqStart && itSeqEnd == t_seqEnd) {
			//this gap is completely recovered
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it = m_tcpSequenceGapList.erase(it);
			result = true;
			continue;
		}
		//if (itSeqStart > t_seqStart && itSeqEnd < t_seqEnd) {
		if (itSeqStart >= t_seqStart && itSeqEnd <= t_seqEnd) {
			//this gap is completely recovered with bigger retransmit
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it = m_tcpSequenceGapList.erase(it);
			result = true;
			retransmit = true;
			continue;
		}
		if (itSeqStart == t_seqStart && itSeqEnd > t_seqEnd) {
			//gap is partially recovered from the start
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it->setSeqGapStart(t_seqEnd);
			result = true;
		}
		if (itSeqStart == t_seqStart && itSeqEnd < t_seqEnd) {
			//gap is completely recovered from the start, some data was retransmitted with this recovery due to network offload
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it = m_tcpSequenceGapList.erase(it);
			result = true;
			retransmit = true;
			continue;
		}
		if (itSeqStart > t_seqStart && itSeqEnd > t_seqEnd && itSeqStart < t_seqEnd) {
			//gap is partially recovered from the start with retransmit that starts earlier than itSeqStart
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it->setSeqGapStart(t_seqEnd);
			result = true;
			retransmit = true;
		}
		if (itSeqStart < t_seqStart && itSeqEnd > t_seqStart && itSeqEnd < t_seqEnd) {
			//gap is partially recovered from the end with retransmit that ends later than itSeqEnd
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it->setSeqGapEnd(t_seqStart);
			result = true;
			retransmit = true;
		}
		if (itSeqStart < t_seqStart && itSeqEnd == t_seqEnd) {
			//gap is partially recovered from the end
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it->setSeqGapEnd(t_seqStart);
			result = true;
		}
		if (itSeqStart < t_seqStart && itSeqEnd > t_seqEnd) {
			//gap is partially recovered in the middle, splitting it for two new gaps
			t_gapFound->setSeqGapStart(itSeqStart);
			t_gapFound->setSeqGapEnd(itSeqEnd);
			it = m_tcpSequenceGapList.erase(it);
			m_tcpSequenceGapList.emplace_back(itSeqStart, t_seqStart);
			m_tcpSequenceGapList.emplace_back(t_seqEnd, itSeqEnd);
			result = true;
			continue;
		}
		//if (it != m_tcpSequenceGapList.end() && it->getSeqGapStart() > it->getSeqGapEnd()) {
		//		log4cpp::Category& logRoot = log4cpp::Category::getRoot();
		//		logRoot.warn("The packet %" PRIu32 " - %" PRIu32 " created a bad gap: %" PRIu32 " - %" PRIu32,
		//					t_seqStart, t_seqEnd, it->getSeqGapStart(), it->getSeqGapEnd());
		//}
		++it;
	}
	return result;
}

void TcpSequenceGaps::addNewGap(const uint32_t t_seqStart, const uint32_t t_seqEnd) {
	if (t_seqEnd > t_seqStart) {
		m_tcpSequenceGapList.emplace_back(t_seqStart, t_seqEnd);
	}
}

size_t TcpSequenceGaps::size() {
	return m_tcpSequenceGapList.size();
}

void TcpSequenceGaps::printGaps() {
	log4cpp::Category& logRoot = log4cpp::Category::getRoot();
	std::list<TcpSequenceGap>::iterator it;
	logRoot.debug("---Print gaps start");
	for (it = m_tcpSequenceGapList.begin(); it != m_tcpSequenceGapList.end(); ++it) {
		logRoot.debug("%" PRIu32 " - %" PRIu32, it->getSeqGapStart(), it->getSeqGapEnd());
	}
	logRoot.debug("---Print gaps end");

}

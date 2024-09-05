/*
 *	PacketDedupRingQueue.cpp
 *
 *	Created on: Apr 11, 2022
 *	Last modified on: Apr 11, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/PacketDedupRingQueue.h"

PacketDedupRingQueue::PacketDedupRingQueue() : m_dq() {
	m_maxSize = 8;
}

bool PacketDedupRingQueue::isDuplicatePacket(uint64_t t_dupId) {

	if (m_dupIdsSet.find(t_dupId) != m_dupIdsSet.end()) {
		   return true;
	}
	if (m_dq.size() == m_maxSize) {
		m_dupIdsSet.erase(m_dupIdsSet.find(m_dq.front()));
		m_dq.pop_front();
	}
	m_dq.push_back(t_dupId);
	m_dupIdsSet.insert(t_dupId);
	return false;
}

void PacketDedupRingQueue::setMaxSize(unsigned int t_maxSize) {
	m_maxSize = t_maxSize;
}

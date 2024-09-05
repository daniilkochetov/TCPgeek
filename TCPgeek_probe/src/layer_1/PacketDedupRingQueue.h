/*
 * PacketDedupRingQueue.h
 *
 *  Created on: Apr 11, 2022
 *	Last modified on: Apr 11, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef PACKETDEDUPRINGQUEUE_H_
#define PACKETDEDUPRINGQUEUE_H_

#include <deque>
#include <unordered_set>
#include <cstdint>

class PacketDedupRingQueue {
private:
	std::deque<uint64_t> m_dq;
	std::unordered_set<uint64_t> m_dupIdsSet;
	unsigned int m_maxSize;
public:
	PacketDedupRingQueue();
	bool isDuplicatePacket(uint64_t t_dupId);
	void setMaxSize(unsigned int t_maxSize);
};

#endif /* PACKETDEDUPRINGQUEUE_H_ */

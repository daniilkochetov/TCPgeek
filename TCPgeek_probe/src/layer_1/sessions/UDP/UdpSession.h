/*
 *	UdpSession.h
 *
 *	Created on: Aug 14, 2023
 *	Last modified on: Aug 14, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef UDPSESSION_H_
#define UDPSESSION_H_


#include <stdint.h>

#include "ProgramProperties.h"
#include "layer_1/KnownPorts.h"
#include "layer_1/sessions/UDP/UdpSessionUpdateResultEnum.h"
#include "layer_1/sessions/TcpUdpSessionKey.h"
#include "layer_1/sessions/IpSession.h"
#include "layer_1/Packet.h"
#include "layer_1/PacketDedupRingQueue.h"
#include "layer_1/StatRecord.h"
#include "SafeQueue.h" // for statistic records queuing

class UdpSession: protected IpSession {
private:
	uint64_t m_clientBytesCounter, m_serverBytesCounter;
	uint64_t m_clientPayloadBytesCounter, m_serverPayloadBytesCounter;
	uint64_t m_clientPacketsCounter, m_serverPacketsCounter;
	uint64_t m_clientDuplicatesCounter, m_serverDuplicatesCounter;
	uint64_t m_clientDuplicatesTotal, m_serverDuplicatesTotal;
	bool m_noDuplicatesFromClient, m_noDuplicatesFromServer; // Prevents excessive verification for duplicates
	uint64_t m_firstClientPacketTimestamp_usec;  //in microseconds
	uint64_t m_firstServerPacketTimestamp_usec;  //in microseconds
	int64_t m_lastSavedTimestamp_sec;
	uint64_t m_lastTimestamp_usec;  //in microseconds

	PacketDedupRingQueue m_packetDedupRingQueue; //ring queue that stores a number of PacketDuplicateId's to identify a duplicate packet
	TcpUdpSessionKey m_udpSessionKey; //contains local and remote IPs' and TCP ports
	StatRecord m_statRecord;

public:

	UdpSession(const Packet* t_packet);
	UdpSessionUpdateResultEnum update(const Packet* t_packet, SafeQueue<StatRecord>* t_statQueue);
	//updates TcpSession object fields and statQueue nodes according to the captured packet
	//invoked only from the main thread of capturing
	//returns true if not out-of-sequence or retransmit, returns false if error must be logged
	void aggregateSessionStat(SafeQueue<StatRecord>* t_statQueue, const int64_t t_previousTimestamp_sec, const int64_t t_currentTimestamp_sec, const uint32_t t_currentTimestamp_usec);
	//aggregates statistics of TCP session in the main thread of capturing and updates statQueue - queue of stat records
	//might be invoked from snifferControl thread with protection of _tcpSessionsMutex when session is terminated as idle
	const TcpUdpSessionKey& getUdpSessionKey() const;

	uint64_t getLastTimestampSec() const;
	int64_t getLastSavedTimestampSec() const;
	uint64_t getLastTimestampUsec() const;
};
#endif /* UDPSESSION_H_ */

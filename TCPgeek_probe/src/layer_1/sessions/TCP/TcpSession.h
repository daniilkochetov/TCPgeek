/*
 *	TcpSession.h
 *
 *	Created on: Mar 30, 2022
 *	Last modified on: Mar 30, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TcpSessions - Describes the TCP session and the ways of its update
 *				Layer 1 - raw data nutrition and its transformation to the
 *				universal data objects that can be used for further analysis.
 */

#ifndef TCPSESSION_H_
#define TCPSESSION_H_





#include <stdlib.h>
#include <string>
#include <cstring>
#include <mutex>  // For std::unique_lock
#include <unordered_set>

#include "ProgramProperties.h"
#include "layer_1/KnownPorts.h"
#include "layer_1/sessions/TcpUdpSessionKey.h"
#include "layer_1/sessions/IpSession.h"
#include "layer_1/StatRecord.h"
#include "layer_1/Packet.h"
#include "layer_1/PacketDedupRingQueue.h"
#include "layer_1/OperationStatusEnum.h"
#include "layer_1/sessions/TCP/TcpSequenceGaps.h"
#include "layer_1/sessions/TCP/TcpSessionUpdateResult.h"
#include "SafeQueue.h" // for statistic records queuing

class TcpSession: protected IpSession {
private:

	//ongoing valuable statistics
	//Retransmits, RTT, Out-of-order
	uint64_t m_clientRetransmits, m_serverRetransmits;
	uint64_t m_clientOutOfOrderCounter, m_serverOutOfOrderCounter;
	uint64_t m_clientRtt, m_serverRtt;
	uint64_t m_clientBytesCounter, m_serverBytesCounter;
	uint64_t m_clientPayloadBytesCounter, m_serverPayloadBytesCounter;
	uint64_t m_clientPacketsCounter, m_serverPacketsCounter;
	uint64_t m_clientDuplicatesCounter, m_serverDuplicatesCounter;
	uint64_t m_clientDuplicatesTotal, m_serverDuplicatesTotal;
	//Operations
	OperationStatusEnum m_operationStatus;
	uint64_t m_operations;
	uint64_t m_clientIdleTime;
	uint64_t m_requestTime;
	uint64_t m_serverThinkTime;
	uint64_t m_responseTime;
	uint64_t m_totalExplainedTime;
	uint64_t m_totalSessionIdleTime;
	u_int32_t m_sessionErrorCode;
	// 0 - Good, otherwise bit mask
	// 2^0 (lower bit) - Connection Refused Error
	// 2^1 - Server Session Termination Error
	// 2^2 - Connection Establishment Timeout Error
	// 2^3 - Server Not Responding Error
	uint64_t m_requestStartTimestamp_usec;
	uint64_t m_responseStartTimestamp_usec;
	//general session control
	uint64_t m_firstTimestamp_usec, m_lastTimestamp_usec;  //in microseconds
	uint64_t m_firstClientPacketTimestamp_usec;  //in microseconds
	uint64_t m_firstServerPacketTimestamp_usec;  //in microseconds
	int64_t m_lastSavedTimestamp_sec;
	u_int32_t m_lastClientSeqNumber, m_lastServerSeqNumber; //can't use last<In|Out>Packet values because of possible TCP out-of-sequence
	u_int32_t m_nextClientSeqNumber, m_nextServerSeqNumber;
	u_int32_t m_acknoledgedSeqNumberForRequests, m_acknoledgedSeqNumberForResponses;
	bool m_clientEndedSession;
	bool m_noDuplicatesFromClient, m_noDuplicatesFromServer; // Prevents excessive verification for duplicates
	Packet m_lastClientPacket, m_lastServerPacket;
	Packet m_lastClientPacketWithPayload, m_lastServerPacketWithPayload;
	TcpSequenceGaps m_clientTcpSequenceGaps; //list of TCP sequence gaps in outbound direction
	TcpSequenceGaps m_serverTcpSequenceGaps; //list of TCP sequence gaps in inbound direction
	PacketDedupRingQueue m_packetDedupRingQueue; //ring queue that stores a number of PacketDuplicateId's to identify a duplicate packet

	TcpUdpSessionKey m_tcpSessionKey; //contains local and remote IPs' and TCP ports

	StatRecord m_statRecord;
	TcpSequenceGap m_gapFound;
	TcpSessionProcessingResultEnum updateSeqGapAndRetransmits(const Packet* t_packet, TcpSequenceGap *t_updateSessionResult, bool t_isRequest);
	//this method checks if new packet is in the right sequence
	//if not it updates the respective TCP sequence gaps list, necessary counters of the statistics
	//and TcpSequenceGap object for TCP packet logging
	//in case of retransmit it updates TcpSequenceGap(a, b) with a = b that points to retransmitted packet sequence number
	//returns true if not out-of-sequence or retransmit, returns false if error must be logged

	void defineRTT(const Packet* t_packet);
	void initTimingForRequestPacket(const Packet* t_packet);



public:
	TcpSession();
	TcpSession(const Packet* t_packet);

	TcpSessionUpdateResult update(const Packet* t_packet, SafeQueue<StatRecord>* t_statQueue);
	//updates TcpSession object fields and statQueue nodes according to the captured packet
	//invoked only from the main thread of capturing
	//returns true if not out-of-sequence or retransmit, returns false if error must be logged
	void aggregateSessionStat(SafeQueue<StatRecord>* t_statQueue, const int64_t t_previousTimestamp_sec, const int64_t t_currentTimestamp_sec, const uint32_t t_currentTimestamp_usec);
	//aggregates statistics of TCP session in the main thread of capturing and updates statQueue - queue of stat records
	//might be invoked from snifferControl thread with protection of _tcpSessionsMutex when session is terminated as idle
	void finalizeOperations();
	const Packet& getLastClientPacket() const;
	const Packet& getLastServerPacket() const;
	uint64_t getLastTimestampUsec() const;
	uint64_t getLastTimestampSec() const;
	const Packet& getLastClientPacketWithPayload() const;
	const Packet& getLastServerPacketWithPayload() const;
	const TcpUdpSessionKey& getTcpSessionKey() const;
	int64_t getLastSavedTimestampSec() const;
};

#endif /* TCPSESSION_H_ */

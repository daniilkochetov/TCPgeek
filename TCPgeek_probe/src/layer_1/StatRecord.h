/*
 *	StatRecord.h
 *
 *  Created on: Mar 28, 2022
 *	Last modified on: Mar 22, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : StatRecord - Describes single statistical record of TCP session.
 *				  Layer 2 - Analysis and logging of data structured at Layer 1
 */

#ifndef STATRECORD_H_
#define STATRECORD_H_

#include "layer_1/sessions/TcpUdpSessionKey.h"

class StatRecord {
private:
	uint64_t m_timestampEpoch;
	TcpUdpSessionKey m_tcpUdpSessionKey;
	u_char m_ipProtocol;
	uint64_t m_clientBytes, m_serverBytes;
	uint64_t m_clientEfficientBytes, m_serverEfficientBytes;
	uint64_t m_clientPackets, m_serverPackets;
	//uint64_t m_currentClientSpeed, m_currentServerSpeed;
	//uint64_t m_currentClientEfficientSpeed, m_currentServerEfficientSpeed;
	uint64_t m_clientDuplicatesCounter, m_serverDuplicatesCounter;
	uint64_t m_clientOutOfOrderCounter, m_serverOutOfOrderCounter;
	uint64_t m_clientActiveSequenceGaps, m_serverActiveSequenceGaps;
	uint64_t m_clientRetransmits, m_serverRetransmits;
	uint64_t m_operations;
	uint64_t m_clientIdleTime;
	uint64_t m_requestTime;
	uint64_t m_serverThinkTime;
	uint64_t m_responseTime;
	uint64_t m_totalSessionIdleTime;
	u_int32_t m_sessionErrorCode;
	uint64_t m_rtt;

public:
	StatRecord();

	void setStatRecord(const uint64_t t_timestampEpoch, const TcpUdpSessionKey t_tcpSessionKey, const u_char t_ipProtocol,
						const uint64_t t_clientBytes, const uint64_t t_serverBytes,
						const uint64_t t_clientEfficientBytes, const uint64_t t_serverEfficientBytes,
						const uint64_t t_clientPackets, const uint64_t t_serverPackets,
						//const uint64_t t_currentClientSpeed, const uint64_t t_currentServerSpeed,
						//const uint64_t t_currentClientEfficientSpeed, const uint64_t t_currentServerEfficientSpeed,
						const uint64_t m_clientDuplicatesCounter, const uint64_t m_serverDuplicatesCounter,
						const uint64_t t_clientOutOfOrderCounter, const uint64_t t_serverOutOfOrderCounter,
						const uint64_t t_clientActiveSequenceGaps, const uint64_t t_serverActiveSequenceGaps,
						const uint64_t t_clientRetransmits,	const uint64_t t_serverRetransmits,
						const uint64_t t_operations, const uint64_t t_clientIdleTime, const uint64_t t_requestTime,
						const uint64_t t_serverThinkTime, const uint64_t t_responseTime,
						const uint64_t t_totalUnexplainedTime, const uint64_t t_totalExplainedTime,
						const uint64_t t_rtt);
	//might be invoked only from the main thread of capturing
	//updates single node of std::list that will be put to the SafeQueue<StatRecord> _statQueue
	//and then stored in the log file during tcp sessions aggregation

	StatRecord& operator = (const StatRecord other)
	{
		m_timestampEpoch = other.m_timestampEpoch;
		m_tcpUdpSessionKey = other.m_tcpUdpSessionKey;
		m_ipProtocol = other.m_ipProtocol;
		m_clientBytes = other.m_clientBytes;
		m_serverBytes = other.m_serverBytes;
		m_clientEfficientBytes = other.m_clientEfficientBytes;
		m_serverEfficientBytes = other.m_serverEfficientBytes;
		m_clientPackets = other.m_clientPackets;
		m_serverPackets = other.m_serverPackets;
		//m_currentClientSpeed = other.m_currentClientSpeed;
		//m_currentServerSpeed = other.m_currentServerSpeed;
		//m_currentClientEfficientSpeed = other.m_currentClientEfficientSpeed;
		//m_currentServerEfficientSpeed = other.m_currentServerEfficientSpeed;
		m_clientDuplicatesCounter = other.m_clientDuplicatesCounter;
		m_serverDuplicatesCounter = other.m_serverDuplicatesCounter;
		m_clientOutOfOrderCounter = other.m_clientOutOfOrderCounter;
		m_serverOutOfOrderCounter = other.m_serverOutOfOrderCounter;
		m_clientActiveSequenceGaps = other.m_clientActiveSequenceGaps;
		m_serverActiveSequenceGaps = other.m_serverActiveSequenceGaps;
		m_clientRetransmits = other.m_clientRetransmits;
		m_serverRetransmits = other.m_serverRetransmits;
		m_operations = other.m_operations;
		m_clientIdleTime = other.m_clientIdleTime;
		m_requestTime = other.m_requestTime;
		m_serverThinkTime = other.m_serverThinkTime;
		m_responseTime = other.m_responseTime;
		m_totalSessionIdleTime = other.m_totalSessionIdleTime;
		m_sessionErrorCode  = other.m_sessionErrorCode;
		m_rtt = other.m_rtt;
		return *this;
	}

	uint64_t getClientPackets() const;
	uint64_t getServerPackets() const;
	uint64_t getRtt() const;
	uint64_t getClientOutOfOrderCounter() const;
	uint64_t getClientRetransmits() const;
	uint64_t getServerOutOfOrderCounter() const;
	uint64_t getServerRetransmits() const;
	uint64_t getClientDuplicatesCounter() const;
	uint64_t getServerDuplicatesCounter() const;
	uint64_t getClientActiveSequenceGaps() const;
	uint64_t getServerActiveSequenceGaps() const;
	uint64_t getOperations() const;
	uint64_t getClientIdleTime() const;
	uint64_t getRequestTime() const;
	uint64_t getResponseTime() const;
	uint64_t getServerThinkTime() const;
	u_int32_t getSessionErrorCode() const;
	uint64_t getTotalSessionIdleTime() const;

	const TcpUdpSessionKey& getTcpUdpSessionKey() const;
	uint64_t getClientBytes() const;
	uint64_t getClientEfficientBytes() const;
	uint64_t getCurrentClientSpeed() const;
	uint64_t getCurrentServerEfficientSpeed() const;
	uint64_t getCurrentServerSpeed() const;
	uint64_t getServerBytes() const;
	uint64_t getServerEfficientBytes() const;
	uint64_t getCurrentClientEfficientSpeed() const;
	u_char getIpProtocol() const;
	uint64_t getTimestampEpoch() const;
};

#endif /* STATRECORD_H_ */

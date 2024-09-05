//=============================================================================
// Name        : StatRecord.cpp
// Author      : Daniil Kochetov unixguide@narod.ru
// Version     : 20220328
// Copyright   : Copyright (C) 2021  Daniil Kochetov
// Description : StatRecord - Describes single statistical record of TCP session.
//
//
//               Layer 2 - Analysis and logging of data structured at Layer 1
//=============================================================================

/*
 *	StatRecord.cpp
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

#include "layer_1/StatRecord.h"

StatRecord::StatRecord() :
				m_timestampEpoch {0},
				m_ipProtocol {0},
				m_clientBytes {0},
				m_serverBytes {0},
				m_clientEfficientBytes {0},
				m_serverEfficientBytes {0},
				m_clientPackets {0},
				m_serverPackets {0},
				m_clientDuplicatesCounter {0},
				m_serverDuplicatesCounter {0},
				m_clientOutOfOrderCounter {0},
				m_serverOutOfOrderCounter {0},
				m_clientActiveSequenceGaps {0},
				m_serverActiveSequenceGaps {0},
				m_clientRetransmits {0},
				m_serverRetransmits {0},
				m_operations {0},
				m_clientIdleTime {0},
				m_requestTime {0},
				m_serverThinkTime {0},
				m_responseTime {0},
				m_totalSessionIdleTime {0},
				m_sessionErrorCode {0},
				m_rtt {0} {

}

void StatRecord::setStatRecord(const uint64_t t_timestampEpoch, const TcpUdpSessionKey t_tcpSessionKey, const u_char t_ipProtocol,
								const uint64_t t_clientBytes, const uint64_t t_serverBytes,
								const uint64_t t_clientEfficientBytes, const uint64_t t_serverEfficientBytes,
								const uint64_t t_clientPackets, const uint64_t t_serverPackets,
//								const uint64_t t_currentClientSpeed, const uint64_t t_currentServerSpeed,
//								const uint64_t t_currentClientEfficientSpeed, const uint64_t t_currentServerEfficientSpeed,
								const uint64_t t_clientDuplicatesCounter, const uint64_t t_serverDuplicatesCounter,
								const uint64_t t_clientOutOfOrderCounter, const uint64_t t_serverOutOfOrderCounter,
								const uint64_t t_clientActiveSequenceGaps, const uint64_t t_serverActiveSequenceGaps,
								const uint64_t t_clientRetransmits,	const uint64_t t_serverRetransmits,
								const uint64_t t_operations, const uint64_t t_clientIdleTime, const uint64_t t_requestTime,
								const uint64_t t_serverThinkTime, const uint64_t t_responseTime,
								const uint64_t t_totalSessionIdleTime, const uint64_t t_sessionErrorCode,
								const uint64_t t_rtt) {
	m_timestampEpoch = t_timestampEpoch;
	m_tcpUdpSessionKey = t_tcpSessionKey;
	m_ipProtocol = t_ipProtocol;
	m_clientBytes = t_clientBytes;
	m_serverBytes = t_serverBytes;
	m_clientEfficientBytes = t_clientEfficientBytes;
	m_serverEfficientBytes = t_serverEfficientBytes;
	m_clientPackets = t_clientPackets;
	m_serverPackets = t_serverPackets;
	//m_currentClientSpeed = t_currentClientSpeed;
	//m_currentServerSpeed = t_currentServerSpeed;
	//m_currentClientEfficientSpeed = t_currentClientEfficientSpeed;
	//m_currentServerEfficientSpeed = t_currentServerEfficientSpeed;
	m_clientDuplicatesCounter = t_clientDuplicatesCounter;
	m_serverDuplicatesCounter = t_serverDuplicatesCounter;
	m_clientOutOfOrderCounter = t_clientOutOfOrderCounter;
	m_serverOutOfOrderCounter = t_serverOutOfOrderCounter;
	m_clientActiveSequenceGaps = t_clientActiveSequenceGaps;
	m_serverActiveSequenceGaps = t_serverActiveSequenceGaps;
	m_clientRetransmits = t_clientRetransmits;
	m_serverRetransmits = t_serverRetransmits;
	m_operations = t_operations;
	m_clientIdleTime = t_clientIdleTime;
	m_requestTime = t_requestTime;
	m_serverThinkTime = t_serverThinkTime;
	m_responseTime = t_responseTime;
	m_totalSessionIdleTime = t_totalSessionIdleTime;
	m_sessionErrorCode = t_sessionErrorCode;
	m_rtt = t_rtt;
}

uint64_t StatRecord::getClientPackets() const {
	return m_clientPackets;
}

uint64_t StatRecord::getServerPackets() const {
	return m_serverPackets;
}

uint64_t StatRecord::getRtt() const {
	return m_rtt;
}

uint64_t StatRecord::getClientOutOfOrderCounter() const {
	return m_clientOutOfOrderCounter;
}

uint64_t StatRecord::getClientRetransmits() const {
	return m_clientRetransmits;
}

uint64_t StatRecord::getServerOutOfOrderCounter() const {
	return m_serverOutOfOrderCounter;
}

uint64_t StatRecord::getServerRetransmits() const {
	return m_serverRetransmits;
}

uint64_t StatRecord::getClientDuplicatesCounter() const {
	return m_clientDuplicatesCounter;
}

uint64_t StatRecord::getServerDuplicatesCounter() const {
	return m_serverDuplicatesCounter;
}

uint64_t StatRecord::getClientActiveSequenceGaps() const {
	return m_clientActiveSequenceGaps;
}

uint64_t StatRecord::getServerActiveSequenceGaps() const {
	return m_serverActiveSequenceGaps;
}

uint64_t StatRecord::getClientIdleTime() const {
	return m_clientIdleTime;
}

uint64_t StatRecord::getRequestTime() const {
	return m_requestTime;
}

uint64_t StatRecord::getResponseTime() const {
	return m_responseTime;
}

uint64_t StatRecord::getServerThinkTime() const {
	return m_serverThinkTime;
}

uint64_t StatRecord::getOperations() const {
	return m_operations;
}

u_int32_t StatRecord::getSessionErrorCode() const {
	return m_sessionErrorCode;
}

uint64_t StatRecord::getClientBytes() const {
	return m_clientBytes;
}

uint64_t StatRecord::getClientEfficientBytes() const {
	return m_clientEfficientBytes;
}

//uint64_t StatRecord::getCurrentClientSpeed() const {
//	return m_currentClientSpeed;
//}

//uint64_t StatRecord::getCurrentServerEfficientSpeed() const {
//	return m_currentServerEfficientSpeed;
//}

//uint64_t StatRecord::getCurrentServerSpeed() const {
//	return m_currentServerSpeed;
//}

//uint64_t StatRecord::getCurrentClientEfficientSpeed() const {
//	return m_currentClientEfficientSpeed;
//}

uint64_t StatRecord::getServerBytes() const {
	return m_serverBytes;
}

uint64_t StatRecord::getServerEfficientBytes() const {
	return m_serverEfficientBytes;
}

const TcpUdpSessionKey& StatRecord::getTcpUdpSessionKey() const {
	return m_tcpUdpSessionKey;
}

uint64_t StatRecord::getTotalSessionIdleTime() const {
	return m_totalSessionIdleTime;
}

u_char StatRecord::getIpProtocol() const {
	return m_ipProtocol;
}

uint64_t StatRecord::getTimestampEpoch() const {
	return m_timestampEpoch;
}

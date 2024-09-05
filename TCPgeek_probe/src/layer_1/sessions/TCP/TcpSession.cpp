/*
 *	TcpSession.cpp
 *
 *	Created on: Mar 30, 2022
 *	Last modified on: May 14, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TcpSession - Describes the TCP session and the ways of its update
 *				Layer 1 - raw data nutrition and its transformation to the
 *				universal data objects that can be used for further analysis.
 */

#include "layer_1/sessions/TCP/TcpSession.h"

TcpSession::TcpSession(const Packet* t_packet) :
						IpSession(t_packet->getIpProtocol()),
						m_clientRetransmits {0},
						m_serverRetransmits {0},
						m_clientOutOfOrderCounter {0},
						m_serverOutOfOrderCounter {0},
						m_clientRtt {0},
						m_serverRtt {0},
						m_clientDuplicatesCounter {0},
						m_serverDuplicatesCounter {0},
						m_clientDuplicatesTotal {0},
						m_serverDuplicatesTotal {0},
						m_operationStatus {OperationStatusEnum::NOT_STARTED},
						m_operations {0},
						m_clientIdleTime {0},
						m_requestTime {0},
						m_serverThinkTime {0},
						m_responseTime {0},
						m_totalExplainedTime {0},
						m_totalSessionIdleTime {0},
						m_sessionErrorCode {0},
						m_requestStartTimestamp_usec {0},
						m_responseStartTimestamp_usec {0},
						m_firstTimestamp_usec {t_packet->getTimestampUsecFull()},
						m_lastTimestamp_usec {t_packet->getTimestampUsecFull()},
						m_firstClientPacketTimestamp_usec {0},
						m_firstServerPacketTimestamp_usec {0},
						m_lastSavedTimestamp_sec {t_packet->getTs().tv_sec},
						m_clientEndedSession {0},
						m_noDuplicatesFromClient {0},
						m_noDuplicatesFromServer {0} {

	if (t_packet->isSynFlag() && (t_packet->isFinFlag() || t_packet->isRstFlag())) return;
	//SYN+FIN and SYN+RST protection
	//TODO: will result in undefined behavior?

	Packet* newTcpPacket = new Packet;
	bool isRequestPacket = true;

	m_packetDedupRingQueue.setMaxSize(ProgramProperties::getDeduplicationBufferSize());
	m_packetDedupRingQueue.isDuplicatePacket(t_packet->getDupId());

	//determining the service port
	//checking several conditions ordered by their probability
	if (t_packet->isSynFlag()) {
		if (!t_packet->isAckFlag()) {
			//this is the first packet of the TCP session
			m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getSrcPort(), t_packet->getDstPort(), t_packet->getSrcIpRaw(), t_packet->getDstIpRaw(), m_ipProtocol);
			isRequestPacket = true;
		} else {
			//this is the second packet of the TCP session
			m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getDstPort(), t_packet->getSrcPort(), t_packet->getDstIpRaw(), t_packet->getSrcIpRaw(), m_ipProtocol);
			isRequestPacket = false;
		}
	} else if (KnownPorts::isKnownPort(t_packet->getDstPort())) {
		//destination port is in the list of known service ports
		m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getSrcPort(), t_packet->getDstPort(), t_packet->getSrcIpRaw(), t_packet->getDstIpRaw(), m_ipProtocol);
		isRequestPacket = true;
	} else if (KnownPorts::isKnownPort(t_packet->getSrcPort())) {
		//source port is in the list of known service ports
		m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getDstPort(), t_packet->getSrcPort(), t_packet->getDstIpRaw(), t_packet->getSrcIpRaw(), m_ipProtocol);
		isRequestPacket = false;
	} else if (t_packet->getDstPort() < 1024) {
		//destination port is in well known port range
		m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getSrcPort(), t_packet->getDstPort(), t_packet->getSrcIpRaw(), t_packet->getDstIpRaw(), m_ipProtocol);
		isRequestPacket = true;
	} else if (t_packet->getSrcPort() < 1024) {
		//source port is in well known port range
		m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getDstPort(), t_packet->getSrcPort(), t_packet->getDstIpRaw(), t_packet->getSrcIpRaw(), m_ipProtocol);
		isRequestPacket = false;
	} else if (t_packet->getSrcPort() > t_packet->getDstPort()) {
		m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getSrcPort(), t_packet->getDstPort(), t_packet->getSrcIpRaw(), t_packet->getDstIpRaw(), m_ipProtocol);
		isRequestPacket = true;
	} else {
		m_tcpSessionKey.updateTcpUdpSessionKey(t_packet->getDstPort(), t_packet->getSrcPort(), t_packet->getDstIpRaw(), t_packet->getSrcIpRaw(), m_ipProtocol);
		isRequestPacket = false;
	}

	if (isRequestPacket) {
		m_serverBytesCounter = 0;
		m_serverPayloadBytesCounter = 0;
		m_clientBytesCounter = t_packet->getTotalLen();
		m_clientPayloadBytesCounter = t_packet->getPayloadlen();

		if (m_clientPayloadBytesCounter > 0) {
			m_lastClientPacketWithPayload = *t_packet;
		} else {
			m_lastClientPacketWithPayload = *newTcpPacket;
		}
		m_lastClientPacket = *t_packet;
		m_lastServerPacketWithPayload = *newTcpPacket;
		m_lastServerPacket = *newTcpPacket;

		m_serverPacketsCounter = 0;
		m_clientPacketsCounter = 1;
		m_lastServerSeqNumber = t_packet->getAckNumber();
		m_lastClientSeqNumber = t_packet->getSequenceNumber();
		m_nextServerSeqNumber = t_packet->getAckNumber();
		m_nextClientSeqNumber = t_packet->getNextSequenceNumber();
		m_acknoledgedSeqNumberForRequests = 0;
		m_acknoledgedSeqNumberForResponses = t_packet->getAckNumber();
		if (t_packet->getPayloadlen() > 0) {
			//First request in the session
			initTimingForRequestPacket(t_packet);
		}
	} else { //this is a response
		m_serverBytesCounter = t_packet->getTotalLen();
		m_serverPayloadBytesCounter = t_packet->getPayloadlen();
		m_clientBytesCounter = 0;
		m_clientPayloadBytesCounter = 0;
		if (m_serverPayloadBytesCounter > 0) {
			m_lastServerPacketWithPayload = *t_packet;
		} else {
			m_lastServerPacketWithPayload = *newTcpPacket;
		}
		m_lastServerPacket = *t_packet;
		m_lastClientPacket = *newTcpPacket;
		m_lastClientPacketWithPayload = *newTcpPacket;

		m_serverPacketsCounter = 1;
		m_clientPacketsCounter = 0;
		m_lastServerSeqNumber = t_packet->getSequenceNumber();
		m_lastClientSeqNumber = t_packet->getAckNumber();
		m_nextServerSeqNumber = t_packet->getNextSequenceNumber();
		m_nextClientSeqNumber = t_packet->getAckNumber();
		m_acknoledgedSeqNumberForRequests = t_packet->getAckNumber();
		m_acknoledgedSeqNumberForResponses = 0;
	}
	delete newTcpPacket;
}

TcpSessionUpdateResult TcpSession::update(const Packet* t_packet, SafeQueue<StatRecord>* t_statQueue) {
	//invoked only from the main thread of capturing


	TcpSessionUpdateResult result;
	u_int64_t measuredServerThinkTime, measuredClientIdleTime;

	IpSession::update(t_packet);

	//this won't change if neither duplicate, out-of-sequence nor retransmit is detected
	m_gapFound.setSeqGapStart(0);
	m_gapFound.setSeqGapEnd(0);

	if ((t_packet->getDstPort() == m_tcpSessionKey.m_serverPort) && (t_packet->getDstIpRaw().s_addr == m_tcpSessionKey.m_serverIpRaw.s_addr)) { //this is a request
		if (m_firstClientPacketTimestamp_usec == 0) {
			m_firstClientPacketTimestamp_usec = t_packet->getTimestampUsecFull();
		}
		if (!m_noDuplicatesFromClient && m_packetDedupRingQueue.isDuplicatePacket(t_packet->getDupId())) {
			//this is a duplicate
			result.tcpSessionProcessingResultEnum = TcpSessionProcessingResultEnum::DUPLICATE;
			m_clientDuplicatesCounter++;
			m_clientDuplicatesTotal++;
		} else {
			m_clientPacketsCounter++;
			result.tcpSessionProcessingResultEnum = updateSeqGapAndRetransmits(t_packet, &m_gapFound, true);
			if (result.tcpSessionProcessingResultEnum != TcpSessionProcessingResultEnum::RETRANSMIT) {
				m_clientPayloadBytesCounter += t_packet->getPayloadlen();
			}
			m_clientBytesCounter += t_packet->getTotalLen();
			result.seqGapStart = m_gapFound.getSeqGapStart();
			result.seqGapEnd = m_gapFound.getSeqGapEnd();
			if (t_packet->isFinFlag() || t_packet->isRstFlag()) {
				m_clientEndedSession = true;
			}
			if (result.tcpSessionProcessingResultEnum == TcpSessionProcessingResultEnum::GOOD_KNOWN) {
				defineRTT(t_packet);
			}
			if (t_packet->getPayloadlen() > 0) {
				if (m_operationStatus == OperationStatusEnum::NOT_STARTED) {
					//First request in the session
					initTimingForRequestPacket(t_packet);
				} else {
					if ((m_operationStatus == OperationStatusEnum::REQUEST_STARTED) && (m_lastClientPacketWithPayload.isPshFlag())) {
						//this is not the first request packet in the session, but the request is split in several datagrams
						m_requestTime += m_lastClientPacketWithPayload.getTimestampUsecFull() - m_requestStartTimestamp_usec;
						m_requestStartTimestamp_usec = t_packet->getTimestampUsecFull();
						m_clientIdleTime += t_packet->getTimestampUsecFull() - m_lastClientPacketWithPayload.getTimestampUsecFull();
					}
					if (m_operationStatus == OperationStatusEnum::RESPONSE_STARTED) {
						//Finishing operation and starting the new one
						m_operations++;
						m_responseTime += m_lastServerPacketWithPayload.getTimestampUsecFull() - m_responseStartTimestamp_usec;
						measuredClientIdleTime = t_packet->getTimestampUsecFull() - m_lastServerPacketWithPayload.getTimestampUsecFull();
						if (measuredClientIdleTime >= m_clientRtt) {
							m_clientIdleTime += measuredClientIdleTime - m_clientRtt;
							m_responseTime += m_clientRtt/2;
							m_requestTime += m_clientRtt/2;
						} else {
							m_responseTime += measuredClientIdleTime/2;
							m_requestTime += measuredClientIdleTime/2;
						}
						m_operationStatus = OperationStatusEnum::REQUEST_STARTED;
						m_requestStartTimestamp_usec = t_packet->getTimestampUsecFull();
					}
				}
				m_lastClientPacketWithPayload = *t_packet;
			}
			m_lastClientPacket = *t_packet;
			if (!m_noDuplicatesFromClient && (m_clientDuplicatesTotal == 0) &&
					(t_packet->getTimestampUsecFull() - m_firstClientPacketTimestamp_usec > ProgramProperties::getDeduplicationTimeout()*1000)) {
			//if (!m_noDuplicatesFromClient && (m_clientDuplicatesTotal == 0) && m_clientPacketsCounter >= t_dedupMaxSize) {
				m_noDuplicatesFromClient = true;
			}
		}
	} else { //this is a response
		if (m_firstServerPacketTimestamp_usec == 0) {
			m_firstServerPacketTimestamp_usec = t_packet->getTimestampUsecFull();
		}
		if (!m_noDuplicatesFromServer && m_packetDedupRingQueue.isDuplicatePacket(t_packet->getDupId())) {
			//this is a duplicate;
			result.tcpSessionProcessingResultEnum = TcpSessionProcessingResultEnum::DUPLICATE;
			m_serverDuplicatesCounter++;
			m_serverDuplicatesTotal++;
		} else {
			if (t_packet->isRstFlag()) {
				if (!m_lastClientPacket.isFinFlag()) {
					if (m_lastClientPacket.isSynFlag()) {
						//Connection Refused Error
						m_sessionErrorCode |= 1;
					} else {
						//Server Session Termination Error
						m_sessionErrorCode |= 2;
					}
				}
			}
			m_serverPacketsCounter++;

			result.tcpSessionProcessingResultEnum = updateSeqGapAndRetransmits(t_packet, &m_gapFound, false);
			if (result.tcpSessionProcessingResultEnum != TcpSessionProcessingResultEnum::RETRANSMIT) {
				m_serverPayloadBytesCounter += t_packet->getPayloadlen();
			}
			m_serverBytesCounter += t_packet->getTotalLen();
			result.seqGapStart = m_gapFound.getSeqGapStart();
			result.seqGapEnd = m_gapFound.getSeqGapEnd();
			if (t_packet->getPayloadlen() > 0) {
				if (m_operationStatus == OperationStatusEnum::REQUEST_STARTED) {
					//Stopping request timer on the last client packet with payload
					m_requestTime += m_lastClientPacketWithPayload.getTimestampUsecFull() - m_requestStartTimestamp_usec;
					measuredServerThinkTime = t_packet->getTimestampUsecFull() - m_lastClientPacketWithPayload.getTimestampUsecFull();
					if (measuredServerThinkTime >= m_serverRtt) {
						m_serverThinkTime += measuredServerThinkTime - m_serverRtt;
						m_requestTime += m_serverRtt/2;
						m_responseTime += m_serverRtt/2;
					} else {
						m_requestTime += measuredServerThinkTime/2;
						m_responseTime += measuredServerThinkTime/2;
					}
					m_responseStartTimestamp_usec = t_packet->getTimestampUsecFull();
					m_operationStatus = OperationStatusEnum::RESPONSE_STARTED;
				}
				m_lastServerPacketWithPayload = *t_packet;
			}
			m_lastServerPacket = *t_packet;
		}
		if (!m_noDuplicatesFromServer && (m_serverDuplicatesTotal == 0) &&
				(t_packet->getTimestampUsecFull() - m_firstServerPacketTimestamp_usec > ProgramProperties::getDeduplicationTimeout()*1000)) {
		//if (!m_noDuplicatesFromServer && (m_serverDuplicatesTotal == 0) && m_serverPacketsCounter >= t_dedupMaxSize) {
			m_noDuplicatesFromServer = true;
		}
	}
	m_lastTimestamp_usec = t_packet->getTimestampUsecFull();

	if((unsigned long)(t_packet->getTs().tv_sec - m_lastSavedTimestamp_sec) >= ProgramProperties::getGranularity()) {
		//m_otherTime = m_lastTimestamp_usec - m_firstTimestamp_usec - m_localTime - m_remoteIdleTime - m_networkTime - m_remoteTime;
		aggregateSessionStat(t_statQueue, m_lastSavedTimestamp_sec, t_packet->getTs().tv_sec, t_packet->getTs().tv_usec);
		m_lastSavedTimestamp_sec = t_packet->getTs().tv_sec;
	}
	result.seqGapStart = m_gapFound.getSeqGapStart();
	result.seqGapEnd = m_gapFound.getSeqGapEnd();
	result.operationStatus = m_operationStatus;
	return result;
}

void TcpSession::initTimingForRequestPacket(const Packet* t_packet) {
	u_int64_t measuredClientIdleTime;

	if (m_lastServerPacket.isSynFlag()) {
		//this is the first packet of the session as it out to be
		m_clientIdleTime = t_packet->getTimestampUsecFull() - m_firstTimestamp_usec - (m_serverRtt + m_clientRtt);
		// Client Idle Time = "Time from the very first packet until now" - "RTT for TCP session setup"
	} else {
		// The session started seen from the middle
		if (m_lastServerPacketWithPayload.getTimestampUsecFull() != 0) {
			// The session started seen from the server response
			measuredClientIdleTime = t_packet->getTimestampUsecFull() - m_lastServerPacketWithPayload.getTimestampUsecFull();
			if (measuredClientIdleTime >= m_clientRtt) {
				m_clientIdleTime += measuredClientIdleTime - m_clientRtt;
			}
		}
	}
	m_requestTime += m_clientRtt/2;
	m_operationStatus = OperationStatusEnum::REQUEST_STARTED;
	m_requestStartTimestamp_usec = t_packet->getTimestampUsecFull();
}

void TcpSession::finalizeOperations() {
	if (m_operationStatus == OperationStatusEnum::RESPONSE_STARTED) {
		m_operations++;
		m_responseTime += m_lastServerPacketWithPayload.getTimestampUsecFull() - m_responseStartTimestamp_usec;
		m_responseTime += m_clientRtt/2;
	} else if (m_sessionErrorCode == 0) {
		if (m_operationStatus == OperationStatusEnum::NOT_STARTED) {
			if (m_lastClientPacket.isSynFlag() && !m_lastServerPacket.isSynFlag()) {
				//Connection Establishment Timeout Error
				m_sessionErrorCode |= 4;
				return;
			}
			//Idle session
		}
		if (m_operationStatus == OperationStatusEnum::REQUEST_STARTED) {
			m_requestTime += m_lastClientPacketWithPayload.getTimestampUsecFull() - m_requestStartTimestamp_usec;
			m_requestTime += m_serverRtt/2;
			//Server Not Responding Error
			if (!m_clientEndedSession) {
				m_sessionErrorCode |= 8;
				return;
			}
		}
	}
}

void TcpSession::defineRTT(const Packet* t_packet) {
	//works only at SYN - SYN/ACK - ACK
	if (m_clientPacketsCounter == 2	&& m_serverPacketsCounter == 1
			&& m_lastClientPacket.isSynFlag() && m_lastServerPacket.isSynFlag() && m_lastServerPacket.isAckFlag()
			&& m_lastServerPacket.getTimestampUsecFull() > m_lastClientPacket.getTimestampUsecFull()) {
			//the previous packet has SYN flag
			m_serverRtt = m_lastServerPacket.getTimestampUsecFull() - m_lastClientPacket.getTimestampUsecFull();
			m_clientRtt = t_packet->getTimestampUsecFull() - m_lastServerPacket.getTimestampUsecFull();
	}
}

TcpSessionProcessingResultEnum TcpSession::updateSeqGapAndRetransmits(const Packet* t_packet, TcpSequenceGap* t_gapFound, bool t_isRequest) {
	//invoked from updateTcpSession only from the main thread
	int64_t seqDiff;
	uint32_t *lastSeqNumberPtr, *expectedNextSeqNumberPtr, *acknoledgedSeqNumberPtr;
	uint64_t *outOfOrderCounterPtr, *retransmitsPtr;
	TcpSequenceGaps *tcpSequenceGaps;

	if (t_isRequest) {
		lastSeqNumberPtr = &m_lastClientSeqNumber;
		expectedNextSeqNumberPtr = &m_nextClientSeqNumber;
		acknoledgedSeqNumberPtr = &m_acknoledgedSeqNumberForResponses;
		outOfOrderCounterPtr = &m_clientOutOfOrderCounter;
		retransmitsPtr = &m_clientRetransmits;
		tcpSequenceGaps = &m_clientTcpSequenceGaps;
	} else {
		lastSeqNumberPtr = &m_lastServerSeqNumber;
		expectedNextSeqNumberPtr = &m_nextServerSeqNumber;
		acknoledgedSeqNumberPtr = &m_acknoledgedSeqNumberForRequests;
		outOfOrderCounterPtr = &m_serverOutOfOrderCounter;
		retransmitsPtr = &m_serverRetransmits;
		tcpSequenceGaps = &m_serverTcpSequenceGaps;
	}


	if (t_packet->isRstFlag()) return TcpSessionProcessingResultEnum::GOOD_KNOWN;
	if (t_packet->isSynFlag()) {
		*lastSeqNumberPtr = t_packet->getSequenceNumber();
		*expectedNextSeqNumberPtr = t_packet->getNextSequenceNumber();
		*acknoledgedSeqNumberPtr = t_packet->getAckNumber();
		return TcpSessionProcessingResultEnum::GOOD_KNOWN;
	}
	if ((t_packet->getPayloadlen() == 0) && (*acknoledgedSeqNumberPtr != t_packet->getAckNumber())) {
		//just ACK t_packet
		*acknoledgedSeqNumberPtr = t_packet->getAckNumber();
		return TcpSessionProcessingResultEnum::GOOD_KNOWN;
	}
	seqDiff = (int64_t) t_packet->getSequenceNumber() - (int64_t) *expectedNextSeqNumberPtr;
	if (seqDiff == 0 || seqDiff == 1 || (seqDiff == -1 && t_packet->getPayloadlen() > 1)) {
		//normal sequence number flow
		//sequence number might increase by 1 in various scenarios, e.g. after FIN
		//seqDiff == -1 with payload would be normal after keep-alive
		*lastSeqNumberPtr = t_packet->getSequenceNumber();
		*expectedNextSeqNumberPtr = t_packet->getNextSequenceNumber();
		*acknoledgedSeqNumberPtr = t_packet->getAckNumber();
		return TcpSessionProcessingResultEnum::GOOD_KNOWN;
	}
	if (seqDiff == -1) {
		*acknoledgedSeqNumberPtr = t_packet->getAckNumber();
		return TcpSessionProcessingResultEnum::KEEPALIVE;
	}
	if (seqDiff > 1 && seqDiff < 1000000000) {
		//new gap in sequence if current t_packet sequence number is higher than expected sequence number
		//_nextSeqNumber is the one that we remember from the previous client t_packet
		//seqDiff < 1000000000 protects against sequence number wrapping around
		tcpSequenceGaps->addNewGap(*expectedNextSeqNumberPtr, t_packet->getSequenceNumber());
		t_gapFound->setSeqGapStart(*expectedNextSeqNumberPtr);
		t_gapFound->setSeqGapEnd(t_packet->getSequenceNumber());
		*lastSeqNumberPtr = t_packet->getSequenceNumber();
		*expectedNextSeqNumberPtr = t_packet->getNextSequenceNumber();
		*acknoledgedSeqNumberPtr = t_packet->getAckNumber();
		*outOfOrderCounterPtr = *outOfOrderCounterPtr + 1;
		return TcpSessionProcessingResultEnum::NEW_GAP;
	}
	if (seqDiff < -1000000000) {
		//t_packet->getSequenceNumber() was cycled to 0, while *expectedNextSeqNumberPtr was not yet
		tcpSequenceGaps->addNewGap(*expectedNextSeqNumberPtr, UINT32_MAX);
		tcpSequenceGaps->addNewGap(0, t_packet->getSequenceNumber());
		t_gapFound->setSeqGapStart(0);
		t_gapFound->setSeqGapEnd(t_packet->getSequenceNumber());
		*lastSeqNumberPtr = t_packet->getSequenceNumber();
		*expectedNextSeqNumberPtr = t_packet->getNextSequenceNumber();
		*acknoledgedSeqNumberPtr = t_packet->getAckNumber();
		*outOfOrderCounterPtr = *outOfOrderCounterPtr + 1;
		return TcpSessionProcessingResultEnum::NEW_GAP;
	}

	//t_packet->getSequenceNumber() < _nextSeqNumber
	bool retramsmitWithOOO = false;
	if (tcpSequenceGaps->gapsContain(t_packet->getSequenceNumber(), t_packet->getNextSequenceNumber(), t_gapFound, retramsmitWithOOO)){
		//t_packet fills one of the previous gap
		*outOfOrderCounterPtr = *outOfOrderCounterPtr + 1;
		if (!retramsmitWithOOO)
			return TcpSessionProcessingResultEnum::GAP_RECOVERY;
	}
	//Retransmit, because if payload == 0, then t_packet->getAckNumber() is higher than current acknowledged bytes,
	//it can also be lower, in case of network offload misguides normal sequence flow
	//if payload > 0 and t_packet->getSequenceNumber() is lower than m_nextClientSeqNumber and the t_packet doesn't belong
	//to any of identified sequence gap

	*retransmitsPtr = *retransmitsPtr + 1;
	seqDiff = (int64_t) t_packet->getNextSequenceNumber() - (int64_t) *expectedNextSeqNumberPtr;
	if (seqDiff > 0 && seqDiff < 1000000000) {
		//sometimes retransmit contains more payload than it was transmitted initially
		//seqDiff < 1000000000 protects against sequence number wrapping around
		*expectedNextSeqNumberPtr = t_packet->getNextSequenceNumber();
	}
	return TcpSessionProcessingResultEnum::RETRANSMIT;
}

void TcpSession::aggregateSessionStat(SafeQueue<StatRecord>* t_statQueue, const int64_t t_previousTimestamp_sec, const int64_t t_currentTimestamp_sec, const uint32_t t_currentTimestamp_usec) {
	//invoked from the main thread of capturing and from snifferControl thread with protection of _tcpSessionsMutex

	m_totalExplainedTime += m_clientIdleTime + m_requestTime + m_serverThinkTime + m_responseTime;
	if ((m_lastTimestamp_usec - m_firstTimestamp_usec) > m_totalExplainedTime) {
		m_totalSessionIdleTime = m_lastTimestamp_usec - m_firstTimestamp_usec - m_totalExplainedTime;
	} else {
		m_totalSessionIdleTime = 0;
	}

	m_statRecord.setStatRecord(t_currentTimestamp_sec * 1000000 + t_currentTimestamp_usec, m_tcpSessionKey, m_ipProtocol, m_clientBytesCounter, m_serverBytesCounter,
								m_clientPayloadBytesCounter, m_serverPayloadBytesCounter, m_clientPacketsCounter, m_serverPacketsCounter,
								m_clientDuplicatesCounter, m_serverDuplicatesCounter,
								m_clientOutOfOrderCounter, m_serverOutOfOrderCounter,
								m_clientTcpSequenceGaps.size(), m_serverTcpSequenceGaps.size(),
								m_clientRetransmits, m_serverRetransmits,
								m_operations, m_clientIdleTime, m_requestTime, m_serverThinkTime, m_responseTime,
								m_totalSessionIdleTime, m_sessionErrorCode,
								m_serverRtt + m_clientRtt);
	t_statQueue->enqueue(m_statRecord);
	m_clientPacketsCounter = 0;
	m_serverPacketsCounter = 0;
	m_clientBytesCounter = 0;
	m_serverBytesCounter = 0;
	m_clientPayloadBytesCounter = 0;
	m_serverPayloadBytesCounter = 0;
	m_clientOutOfOrderCounter = 0;
	m_serverOutOfOrderCounter = 0;
	m_clientRetransmits = 0;
	m_serverRetransmits = 0;
	m_clientDuplicatesCounter = 0;
	m_serverDuplicatesCounter = 0;
	m_operations = 0;
	m_clientIdleTime = 0;
	m_requestTime = 0;
	m_serverThinkTime = 0;
	m_responseTime = 0;
	//DEBUG
	//log4cpp::Category& logRoot = log4cpp::Category::getRoot();
	//logRoot.debug("ClientTcpSequenceGaps are:");
	//m_clientTcpSequenceGaps.printGaps();
	//logRoot.debug("ServerTcpSequenceGaps are:");
	//m_serverTcpSequenceGaps.printGaps();
	//!DEBUG
}

const Packet& TcpSession::getLastClientPacket() const {
	return m_lastClientPacket;
}

const Packet& TcpSession::getLastServerPacket() const {
	return m_lastServerPacket;
}

uint64_t TcpSession::getLastTimestampUsec() const {
	return m_lastTimestamp_usec;
}

uint64_t TcpSession::getLastTimestampSec() const {
	return m_lastTimestamp_usec/1000000;
}

const Packet& TcpSession::getLastClientPacketWithPayload() const {
	return m_lastClientPacketWithPayload;
}

const Packet& TcpSession::getLastServerPacketWithPayload() const {
	return m_lastServerPacketWithPayload;
}

const TcpUdpSessionKey& TcpSession::getTcpSessionKey() const {
	return m_tcpSessionKey;
}

int64_t TcpSession::getLastSavedTimestampSec() const {
	return m_lastSavedTimestamp_sec;
}



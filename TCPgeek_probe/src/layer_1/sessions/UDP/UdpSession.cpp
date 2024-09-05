/*
 *	UdpSession.cpp
 *
 *	Created on: Aug 14, 2023
 *	Last modified on: Aug 14, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/sessions/UDP/UdpSession.h"

UdpSession::UdpSession(const Packet* t_packet) :
										IpSession(t_packet->getIpProtocol()),
										m_clientDuplicatesCounter {0},
										m_serverDuplicatesCounter {0},
										m_clientDuplicatesTotal {0},
										m_serverDuplicatesTotal {0},
										m_noDuplicatesFromClient {0},
										m_noDuplicatesFromServer {0},
										m_firstClientPacketTimestamp_usec {0},
										m_firstServerPacketTimestamp_usec {0},
										m_lastSavedTimestamp_sec {t_packet->getTs().tv_sec},
										m_lastTimestamp_usec {t_packet->getTimestampUsecFull()} {

	bool isRequestPacket = true;

	m_packetDedupRingQueue.setMaxSize(ProgramProperties::getDeduplicationBufferSize());
	m_packetDedupRingQueue.isDuplicatePacket(t_packet->getDupId());

	if (KnownPorts::isKnownPort(t_packet->getDstPort())) {
		//destination port is in the list of known service ports
		m_udpSessionKey.updateTcpUdpSessionKey(t_packet->getSrcPort(), t_packet->getDstPort(), t_packet->getSrcIpRaw(), t_packet->getDstIpRaw(), m_ipProtocol);
		isRequestPacket = true;
	} else if (KnownPorts::isKnownPort(t_packet->getSrcPort())) {
		//source port is in the list of known service ports
		m_udpSessionKey.updateTcpUdpSessionKey(t_packet->getDstPort(), t_packet->getSrcPort(), t_packet->getDstIpRaw(), t_packet->getSrcIpRaw(), m_ipProtocol);
		isRequestPacket = false;
	} else if (t_packet->getDstPort() < 1024) {
		//destination port is in well known port range
		m_udpSessionKey.updateTcpUdpSessionKey(t_packet->getSrcPort(), t_packet->getDstPort(), t_packet->getSrcIpRaw(), t_packet->getDstIpRaw(), m_ipProtocol);
		isRequestPacket = true;
	} else if (t_packet->getSrcPort() < 1024) {
		//source port is in well known port range
		m_udpSessionKey.updateTcpUdpSessionKey(t_packet->getDstPort(), t_packet->getSrcPort(), t_packet->getDstIpRaw(), t_packet->getSrcIpRaw(), m_ipProtocol);
		isRequestPacket = false;
	} else if (t_packet->getSrcPort() > t_packet->getDstPort()) {
		m_udpSessionKey.updateTcpUdpSessionKey(t_packet->getSrcPort(), t_packet->getDstPort(), t_packet->getSrcIpRaw(), t_packet->getDstIpRaw(), m_ipProtocol);
		isRequestPacket = true;
	} else {
		m_udpSessionKey.updateTcpUdpSessionKey(t_packet->getDstPort(), t_packet->getSrcPort(), t_packet->getDstIpRaw(), t_packet->getSrcIpRaw(), m_ipProtocol);
		isRequestPacket = false;
	}
	if (isRequestPacket) {
		m_serverBytesCounter = 0;
		m_serverPayloadBytesCounter = 0;
		m_clientBytesCounter = t_packet->getTotalLen();
		m_clientPayloadBytesCounter = t_packet->getPayloadlen();
		m_serverPacketsCounter = 0;
		m_clientPacketsCounter = 1;
	} else { //this is a response
		m_serverBytesCounter = t_packet->getTotalLen();
		m_serverPayloadBytesCounter = t_packet->getPayloadlen();
		m_clientBytesCounter = 0;
		m_clientPayloadBytesCounter = 0;
		m_serverPacketsCounter = 1;
		m_clientPacketsCounter = 0;
	}
}

UdpSessionUpdateResultEnum UdpSession::update(const Packet* t_packet, SafeQueue<StatRecord>* t_statQueue) {

	IpSession::update(t_packet);
	UdpSessionUpdateResultEnum result = UdpSessionUpdateResultEnum::VOID;

	if ((t_packet->getDstPort() == m_udpSessionKey.m_serverPort) && (t_packet->getDstIpRaw().s_addr == m_udpSessionKey.m_serverIpRaw.s_addr)) { //this is a request
		if (m_firstClientPacketTimestamp_usec == 0) {
			m_firstClientPacketTimestamp_usec = t_packet->getTimestampUsecFull();
		}
		if (!m_noDuplicatesFromClient && m_packetDedupRingQueue.isDuplicatePacket(t_packet->getDupId())) {
			//this is a duplicate
			result = UdpSessionUpdateResultEnum::DUPLICATE;
			m_clientDuplicatesCounter++;
			m_clientDuplicatesTotal++;
		} else {
			m_clientPacketsCounter++;
			m_clientBytesCounter += t_packet->getTotalLen();
			m_clientPayloadBytesCounter += t_packet->getPayloadlen();
		}
		if (!m_noDuplicatesFromClient && (m_clientDuplicatesTotal == 0) &&
			(t_packet->getTimestampUsecFull() - m_firstClientPacketTimestamp_usec > ProgramProperties::getDeduplicationTimeout()*1000)) {
			//if (!m_noDuplicatesFromClient && (m_clientDuplicatesTotal == 0) && m_clientPacketsCounter >= t_dedupMaxSize) {
			m_noDuplicatesFromClient = true;
		}
	} else { //this is a response
		if (m_firstServerPacketTimestamp_usec == 0) {
			m_firstServerPacketTimestamp_usec = t_packet->getTimestampUsecFull();
		}
		if (!m_noDuplicatesFromServer && m_packetDedupRingQueue.isDuplicatePacket(t_packet->getDupId())) {
			//this is a duplicate;
			result = UdpSessionUpdateResultEnum::DUPLICATE;
			m_serverDuplicatesCounter++;
			m_serverDuplicatesTotal++;
		} else {
			m_serverPacketsCounter++;
			m_serverBytesCounter += t_packet->getTotalLen();
			m_serverPayloadBytesCounter += t_packet->getPayloadlen();
		}
		if (!m_noDuplicatesFromClient && (m_clientDuplicatesTotal == 0) &&
			(t_packet->getTimestampUsecFull() - m_firstClientPacketTimestamp_usec > ProgramProperties::getDeduplicationTimeout()*1000)) {
			//if (!m_noDuplicatesFromClient && (m_clientDuplicatesTotal == 0) && m_clientPacketsCounter >= t_dedupMaxSize) {
			m_noDuplicatesFromServer = true;
		}
	}
	m_lastTimestamp_usec = t_packet->getTimestampUsecFull();
	if((unsigned long)(t_packet->getTs().tv_sec - m_lastSavedTimestamp_sec) >= ProgramProperties::getGranularity()) {
		//m_otherTime = m_lastTimestamp_usec - m_firstTimestamp_usec - m_localTime - m_remoteIdleTime - m_networkTime - m_remoteTime;
		aggregateSessionStat(t_statQueue, m_lastSavedTimestamp_sec, t_packet->getTs().tv_sec, t_packet->getTs().tv_usec);
		m_lastSavedTimestamp_sec = t_packet->getTs().tv_sec;
	}

	return result;
}

const TcpUdpSessionKey& UdpSession::getUdpSessionKey() const {
	return m_udpSessionKey;
}

void UdpSession::aggregateSessionStat(SafeQueue<StatRecord>* t_statQueue,
		const int64_t t_previousTimestamp_sec,
		const int64_t t_currentTimestamp_sec,
		const uint32_t t_currentTimestamp_usec) {
	//invoked from the main thread of capturing and from snifferControl thread with protection of _tcpSessionsMutex
	//uint64_t currentClientEfficientSpeed, currentServerEfficientSpeed;
	//uint64_t currentClientSpeed, currentServerSpeed;
	//float diffTime_sec;

	//if (t_currentTimestamp_sec > t_previousTimestamp_sec) {
	//	diffTime_sec = t_currentTimestamp_sec - t_previousTimestamp_sec;
	//	currentClientSpeed = m_clientBytesCounter/diffTime_sec;
	//	currentServerSpeed = m_serverBytesCounter/diffTime_sec;
	//	currentClientEfficientSpeed = m_clientPayloadBytesCounter/diffTime_sec;
	//	currentServerEfficientSpeed = m_serverPayloadBytesCounter/diffTime_sec;
	//} else {
	//	currentClientSpeed = 0;
	//	currentServerSpeed = 0;
	//	currentClientEfficientSpeed = 0;
	//	currentServerEfficientSpeed = 0;
	//}

	m_statRecord.setStatRecord(t_currentTimestamp_sec*1000000 + t_currentTimestamp_usec, m_udpSessionKey, m_ipProtocol, m_clientBytesCounter, m_serverBytesCounter,
							    m_clientPayloadBytesCounter, m_serverPayloadBytesCounter, m_clientPacketsCounter, m_serverPacketsCounter,
								//currentClientSpeed, currentServerSpeed, currentClientEfficientSpeed, currentServerEfficientSpeed,
								m_clientDuplicatesCounter, m_serverDuplicatesCounter,
								0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	t_statQueue->enqueue(m_statRecord);
	m_clientPacketsCounter = 0;
	m_serverPacketsCounter = 0;
	m_clientBytesCounter = 0;
	m_serverBytesCounter = 0;
	m_clientPayloadBytesCounter = 0;
	m_serverPayloadBytesCounter = 0;
	m_clientDuplicatesCounter = 0;
	m_serverDuplicatesCounter = 0;
}

int64_t UdpSession::getLastSavedTimestampSec() const {
	return m_lastSavedTimestamp_sec;
}

uint64_t UdpSession::getLastTimestampSec() const {
	return m_lastTimestamp_usec/1000000;
}

uint64_t UdpSession::getLastTimestampUsec() const {
	return m_lastTimestamp_usec;
}

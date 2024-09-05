/*
 *	UdpSessions.cpp
 *
 *	Created on: Aug 14, 2023
 *	Last modified on: Aug 14, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/sessions/UDP/UdpSessions.h"

UdpSessions::UdpSessions(SafeQueue<StatRecord>* t_statQueue): m_statQueue {t_statQueue} {
	m_udpSessionProcessingResult = UdpSessionUpdateResultEnum::VOID;
	m_udpSessionsMap.clear();
}

const std::size_t UdpSessions::size() const {
	return m_udpSessionsMap.size();
}

UdpSessionUpdateResultEnum UdpSessions::update(const Packet* t_packet) {



	UdpSessionUpdateResultEnum result;
	std::unordered_map<TcpUdpSessionKey, UdpSession, TcpUdpSessionHashFn>::iterator sessionsIterator;
	TcpUdpSessionKey* clientPacketSessionKey;
	TcpUdpSessionKey* serverPacketSessionKey;

	result = UdpSessionUpdateResultEnum::VOID;
	//at this moment we don't know if this is a request or response, so considering both options
	clientPacketSessionKey = new TcpUdpSessionKey(t_packet->getSrcPort(), //client port
														t_packet->getDstPort(), //server port
														t_packet->getSrcIpRaw(), //client IP
														t_packet->getDstIpRaw(),
														t_packet->getIpProtocol()); //server IP
	serverPacketSessionKey = new TcpUdpSessionKey(t_packet->getDstPort(), //client port
														t_packet->getSrcPort(), //server port
														t_packet->getDstIpRaw(), //client IP
														t_packet->getSrcIpRaw(), //server IP
														t_packet->getIpProtocol());
	{
		std::lock_guard<std::mutex> guard(m_udpSessionsMutex); //preventing control thread from reading in the same time
		sessionsIterator = m_udpSessionsMap.find(*clientPacketSessionKey);
		if (sessionsIterator == m_udpSessionsMap.end()) {
			sessionsIterator = m_udpSessionsMap.find(*serverPacketSessionKey);
		}

		if (sessionsIterator == m_udpSessionsMap.end()) {
			//this packet doesn't belong to any known UDP session, hence this is a new session
			if (m_udpSessionsMap.size() < ProgramProperties::getMaxTcpSessions()) {
				UdpSession* newSession = new UdpSession(t_packet);
				m_udpSessionsMap.insert(std::make_pair(newSession->getUdpSessionKey(),*newSession));
					delete newSession;
					result = UdpSessionUpdateResultEnum::GOOD_NEW;
				}
			} else {
				//this packet updates known TCP session
				result = sessionsIterator->second.update(t_packet, m_statQueue);
				if (result != UdpSessionUpdateResultEnum::DUPLICATE) {
					result = UdpSessionUpdateResultEnum::GOOD_KNOWN;
				}
			}
	}
	delete clientPacketSessionKey;
	delete serverPacketSessionKey;
	return result;
}

uint32_t UdpSessions::cleanIdleSessions() {
	uint32_t erasedSessions = 0;
	std::unordered_map<TcpUdpSessionKey, UdpSession, TcpUdpSessionHashFn>::iterator sessionsIterator;
	{
		std::lock_guard<std::mutex> guard(m_udpSessionsMutex);
		sessionsIterator = m_udpSessionsMap.begin();
		while (sessionsIterator != m_udpSessionsMap.end()) {
			if (std::time(nullptr) - sessionsIterator->second.getLastTimestampSec()  > ProgramProperties::getIdleTcpSessionTimeout()) {
				//this session is idle, so removing it from the map
				sessionsIterator->second.aggregateSessionStat(m_statQueue, sessionsIterator->second.getLastSavedTimestampSec(),
															sessionsIterator->second.getLastTimestampSec(), sessionsIterator->second.getLastTimestampUsec() % 1000000);
				sessionsIterator = m_udpSessionsMap.erase(sessionsIterator);
				erasedSessions++;
			} else
				sessionsIterator++;
		}
	}
	return erasedSessions;
}

uint32_t UdpSessions::finalStatCalculation() {
	uint32_t erasedSessions {0};
	std::unordered_map<TcpUdpSessionKey, UdpSession, TcpUdpSessionHashFn>::iterator sessionsIterator;

	sessionsIterator = m_udpSessionsMap.begin();
	while (sessionsIterator != m_udpSessionsMap.end()) {
		{
			std::lock_guard<std::mutex> guard(m_udpSessionsMutex);
			sessionsIterator->second.aggregateSessionStat(m_statQueue, sessionsIterator->second.getLastSavedTimestampSec(),
														sessionsIterator->second.getLastTimestampSec(), sessionsIterator->second.getLastTimestampUsec() % 1000000);
			sessionsIterator = m_udpSessionsMap.erase(sessionsIterator);
		}
		erasedSessions++;
	}
	return erasedSessions;
}

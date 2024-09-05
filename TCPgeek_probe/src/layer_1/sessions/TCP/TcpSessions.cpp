/*
 *	TcpSessions.cpp
 *
 *	Created on: Mar 30, 2022
 *	Last modified on: May 14, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TcpSessions - Describes the way of thread safe management of the
 *					std::unordered_map collection of TCP sessions
 *				Layer 1 - raw data nutrition and its transformation to the
 *				universal data objects that can be used for further analysis.
 */


#include "layer_1/sessions/TCP/TcpSessions.h"

TcpSessions::TcpSessions(SafeQueue<StatRecord>* t_statQueue) : m_statQueue {t_statQueue} {
	m_tcpSessionProcessingResultEnum = TcpSessionProcessingResultEnum::VOID;
	m_tcpSessionsMap.clear();
}

TcpSessions::~TcpSessions() {
	//delete _updateSessionResult;
}

const std::size_t TcpSessions::size() const {
	return m_tcpSessionsMap.size();
}

TcpSessionUpdateResult TcpSessions::update(const Packet* t_packet) {

	//!DEBUG
		u_int64_t startCycles, endCycles;
		startCycles = SelfMonitor::getCpuTicks();
	//------

	TcpSessionUpdateResult result;
	std::unordered_map<TcpUdpSessionKey, TcpSession, TcpUdpSessionHashFn>::iterator sessionsIterator;
	TcpUdpSessionKey* clientPacketTcpSessionKey;
	TcpUdpSessionKey* serverPacketTcpSessionKey;

	result.tcpSessionProcessingResultEnum = TcpSessionProcessingResultEnum::VOID;
	result.operationStatus = OperationStatusEnum::NOT_STARTED;
	result.debugCpuCycles0 = 0;
	result.debugCpuCycles1 = 0;
	result.debugCpuCycles2 = 0;

	//at this moment we don't know if this is a request or response, so considering both options
	clientPacketTcpSessionKey = new TcpUdpSessionKey(t_packet->getSrcPort(), //client port
													t_packet->getDstPort(), //server port
													t_packet->getSrcIpRaw(), //client IP
													t_packet->getDstIpRaw(),
													t_packet->getIpProtocol()); //server IP
	serverPacketTcpSessionKey = new TcpUdpSessionKey(t_packet->getDstPort(), //client port
													t_packet->getSrcPort(), //server port
													t_packet->getDstIpRaw(), //client IP
													t_packet->getSrcIpRaw(), //server IP
													t_packet->getIpProtocol());
	{
		std::lock_guard<std::mutex> guard(m_tcpSessionsMutex); //preventing control thread from reading in the same time

		sessionsIterator = m_tcpSessionsMap.find(*clientPacketTcpSessionKey);
		if (sessionsIterator == m_tcpSessionsMap.end()) {
			sessionsIterator = m_tcpSessionsMap.find(*serverPacketTcpSessionKey);
		}

		if (t_packet->isSynFlag() && !t_packet->isAckFlag() && (sessionsIterator != m_tcpSessionsMap.end())) {
			//there can be SYN packet of new session, while the session with the same TcpSessionKey persists in the m_tcpSessionsMap
			//in this case we aggregate and erase this session and create a new one instead
			if (!sessionsIterator->second.getLastClientPacket().isSynFlag()) {
				//protection against duplicate SYN
				sessionsIterator->second.aggregateSessionStat(m_statQueue, sessionsIterator->second.getLastSavedTimestampSec(),
															sessionsIterator->second.getLastTimestampSec(), sessionsIterator->second.getLastTimestampUsec() % 1000000);
				sessionsIterator = m_tcpSessionsMap.erase(sessionsIterator);
				sessionsIterator = m_tcpSessionsMap.end();
			}
		}
		if (sessionsIterator == m_tcpSessionsMap.end()) {
			//this packet doesn't belong to any known TCP session, hence this is a new session
			if (!t_packet->isRstFlag() && (m_tcpSessionsMap.size() < ProgramProperties::getMaxTcpSessions())) {
				TcpSession* newSession = new TcpSession(t_packet);
				m_tcpSessionsMap.insert(std::make_pair(newSession->getTcpSessionKey(),*newSession));
				delete newSession;
				result.tcpSessionProcessingResultEnum = TcpSessionProcessingResultEnum::GOOD_NEW;
			}
		} else {
			//this packet updates known TCP session
			result = sessionsIterator->second.update(t_packet, m_statQueue);
		}

	}
	delete clientPacketTcpSessionKey;
	delete serverPacketTcpSessionKey;

	//!DEBUG
		endCycles = SelfMonitor::getCpuTicks();
		result.debugCpuCycles0 = endCycles - startCycles;
	//------

	return result;
}

uint32_t TcpSessions::cleanIdleSessions() {

	uint32_t erasedSessions = 0;
	std::unordered_map<TcpUdpSessionKey, TcpSession, TcpUdpSessionHashFn>::iterator sessionsIterator;
	{
		std::lock_guard<std::mutex> guard(m_tcpSessionsMutex);
		sessionsIterator = m_tcpSessionsMap.begin();
		while (sessionsIterator != m_tcpSessionsMap.end()) {
			if (std::time(nullptr) - sessionsIterator->second.getLastTimestampSec()  > ProgramProperties::getIdleTcpSessionTimeout()) {
			//this session is idle, so removing it from the map

				sessionsIterator->second.finalizeOperations();
				sessionsIterator->second.aggregateSessionStat(m_statQueue, sessionsIterator->second.getLastSavedTimestampSec(),
																sessionsIterator->second.getLastTimestampSec(), sessionsIterator->second.getLastTimestampUsec() % 1000000);
				sessionsIterator = m_tcpSessionsMap.erase(sessionsIterator);
				erasedSessions++;
			} else
				sessionsIterator++;
		}
	}
	return erasedSessions;
}

uint32_t TcpSessions::finalStatCalculation() {

	uint32_t erasedSessions {0};
	std::unordered_map<TcpUdpSessionKey, TcpSession, TcpUdpSessionHashFn>::iterator sessionsIterator;

	sessionsIterator = m_tcpSessionsMap.begin();
	while (sessionsIterator != m_tcpSessionsMap.end()) {
		{
			std::lock_guard<std::mutex> guard(m_tcpSessionsMutex);
			sessionsIterator->second.finalizeOperations();
			sessionsIterator->second.aggregateSessionStat(m_statQueue, sessionsIterator->second.getLastSavedTimestampSec(),
														sessionsIterator->second.getLastTimestampSec(), sessionsIterator->second.getLastTimestampUsec() % 1000000);
			sessionsIterator = m_tcpSessionsMap.erase(sessionsIterator);
		}
		erasedSessions++;
	}
	return erasedSessions;
}

/*
 *	TcpSessions.h
 *
 *	Created on: Mar 30, 2022
 *	Last modified on: Mar 30, 2022
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


#ifndef TCPSESSIONS_H_
#define TCPSESSIONS_H_

#include <mutex>  // For std::unique_lock
#include <unordered_map>
#include <cstdlib>

#include <log4cpp/Category.hh>
#include "ProgramProperties.h"
#include "SelfMonitor.h"
#include "layer_1/KnownPorts.h"
#include "layer_1/sessions/TcpUdpSessionKey.h"
#include "layer_1/sessions/TCP/TcpSession.h"
#include "layer_1/sessions/TCP/TcpSessionUpdateResult.h"



class TcpSessions {
private:
	mutable std::mutex m_tcpSessionsMutex;
	std::unordered_map<TcpUdpSessionKey, TcpSession, TcpUdpSessionHashFn> m_tcpSessionsMap;
	SafeQueue<StatRecord>* m_statQueue;
	TcpSessionProcessingResultEnum m_tcpSessionProcessingResultEnum;

public:

	TcpSessions(SafeQueue<StatRecord>* t_statQueue);
	//creates TCPSessions object based on std::unordered_map
	//takes initial parameters from the configuration file
	//uses the pointer at the statistics queue defined at Sniffer object
	~TcpSessions();
	//re-implements size method of std::unordered_map for logging
	const std::size_t size() const;
	//every new captured and successfully parsed packet updates the map
	TcpSessionUpdateResult update(const Packet* t_packet);
	uint32_t finalStatCalculation();
	uint32_t cleanIdleSessions();
	//invoked from snifferControl thread with protection of _tcpSessionsMutex
	//iterates thought all the sessions in the map identifying idle ones
	//aggregates their stat and removes them from the map
};

#endif /* TCPSESSIONS_H_ */

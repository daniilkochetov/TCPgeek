/*
 *	UdpSessions.h
 *
 *	Created on: Aug 14, 2023
 *	Last modified on: Aug 14, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef UDPSESSIONS_H_
#define UDPSESSIONS_H_

#include <mutex>  // For std::unique_lock
#include <unordered_map>
#include <cstdlib>
#include <log4cpp/Category.hh>

#include "ProgramProperties.h"
#include "layer_1/KnownPorts.h"
#include "layer_1/sessions/UDP/UdpSession.h"
#include "layer_1/sessions/TcpUdpSessionKey.h"
#include "layer_1/StatRecord.h"
#include "SafeQueue.h"


class UdpSessions {
private:
  mutable std::mutex m_udpSessionsMutex;
  std::unordered_map<TcpUdpSessionKey, UdpSession, TcpUdpSessionHashFn> m_udpSessionsMap;
  SafeQueue<StatRecord>* m_statQueue;
  UdpSessionUpdateResultEnum m_udpSessionProcessingResult;


public:

	UdpSessions(SafeQueue<StatRecord>* t_statQueue);
	//creates TCPSessions object based on std::unordered_map
	//takes initial parameters from the configuration file
	//uses the pointer at the statistics queue defined at Sniffer object


	const std::size_t size() const;
	//re-implements size method of std::unordered_map for logging

	UdpSessionUpdateResultEnum update(const Packet* t_packet);
	//every new captured and successfully parsed packet updates the map
	uint32_t finalStatCalculation();

	uint32_t cleanIdleSessions();
	//invoked from snifferControl thread with protection of m_udpSessionsMutex
	//iterates thought all the sessions in the map identifying idle ones
	//aggregates their stat and removes them from the map
};

#endif /* UDPSESSIONS_H_ */

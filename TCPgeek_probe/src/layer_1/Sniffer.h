/*
 *	Sniffer.h
 *
 *  Created on: Mar 28, 2022
 *	Last modified on: Mar 28, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : Sniffer - Main class for capturing.
 *					Implements libpcap functionality. It defines the way to start/stop
 *					capture and initiate each packet processing.
 *					This class instantiates TcpPacket and TcpSessions objects.
 *				  Layer 1 - raw data nutrition and its transformation to the
 *				  	universal data objects that can be used for further analysis.
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_

#define SESSION_KEY_STR_MAX_SIZE 44

#include <pcap.h> // for pcap_t and bpf_program
#include <condition_variable> // for std::condition_variable _ongoing
#include <log4cpp/Category.hh> // for logging capabilities
#include <ctime> // for self performance measurement
#include <mutex>  // For std::unique_lock
#include <csignal>
#include <stdint.h>
#include <string>
#include <unistd.h>

#include "ProgramProperties.h"
#include "layer_1/sessions/TCP/TcpSequenceGap.h" // for logging session gaps and retransmits
#include "layer_1/sessions/TCP/TcpSessions.h" // for TcpSessions *_tcpSessions;
#include "layer_1/sessions/UDP/UdpSessions.h"
#include "layer_1/sessions/TCP/TcpSessionUpdateResult.h"
#include "layer_1/PacketStatRecordLogger.h"
#include "layer_1/Packet.h" // for TcpPacket *_newPacket;
#include "layer_1/PacketProcessingResultEnum.h"
#include "layer_1/KnownPorts.h"
#include "layer_1/networkHeaders.h" // for TCP and IP network headers format and related constants
#include "layer_1/LocalSubnets.h"
#include "SelfMonitor.h"
#include "layer_1/StatWriter.h"

class Sniffer {
private:
	//****PROPERTIES FOR CAPTURING****
	bool m_isOffline; //true if pcap file is a source
	pcap_t *m_handle; //packet capture handle
	struct bpf_program m_bpf; //to store compiled packet filter
	struct pcap_stat* m_pcapStat; //this is where general statistics of capturing would be put at the end of capture
	int m_linkType; //DLT_EN10MB, DLT_LINUX_SLL or unknown


	StatWriter* m_statWriter;
	Packet m_newPacket;
	//every time the sniffer processes a new packet within gotPacket() it fills m_newPacket properties accordingly
	//m_newPacket instantiated in a constructor only once per process lifetime
	//this way I avoid many memory allocations/deallocations within gotPacket() method


	SafeQueue<StatRecord>* m_sessionsStatQueue;
	//thread safe queue of TCP sessions statistics records: enqueued with packet capturing thread, dequeued with control thread

	TcpSessions *m_tcpSessions;
	//unordered_map based collection of active TCP sessions
	UdpSessions *m_udpSessions;
	//unordered_map based collection of active UDP sessions

	const KnownPorts* m_knownPorts;
	//set of known ports for simple distinguishing requests and responses
	LocalSubnets* m_localSubnets;

	//****PACKET DEBUG/STATISTICS PROPERTIES****
	//defines if we going to spend time on debugging of each packet, depends on packetLog level
	bool m_isDebugPacketOn;
	//this is where detailed information would be stored for the m_newPacket, only if m_isDebugPacketOn == true
	char *m_debugPacketInfo;
	//this property represents additional details about TCP sequence gap if it was detected during TCP session update
	//this way I can reflect them in packetStatRecord if m_isDebugPacketOn == true
	TcpSequenceGap *m_identifiedSequenceGap;
	//single packet info record
	PacketStatRecord m_pcktStatRecord;
	//thread safe queue of TCP packets statistics records: enqueued with packet capturing thread, dequeued with control thread
	SafeQueue<PacketStatRecord> m_packetStatQueue;
	//this is the object to write packet statistics on disk
	PacketStatRecordLogger m_pcktStatRecordLogger;

	//****SELF MONITOR****
	//to understand CPU and memory used by this program
	SelfMonitor m_selfMonitor;
	mutable std::mutex m_processingPerformanceMutex;
	u_int32_t m_ps_drop_prev;
	//to understand processing time details
	u_int64_t m_pktProcessingCyclesSubTotal;
	u_int64_t m_pktsProcessedSubTotal;
	u_int64_t m_tcpPktDebugCpuCyclesSubTotal0;
	u_int64_t m_tcpPktDebugedSubTotal0;
	u_int64_t m_tcpPktDebugCpuCyclesSubTotal1;
	u_int64_t m_tcpPktDebugedSubTotal1;
	u_int64_t m_tcpPktDebugCpuCyclesSubTotal2;
	u_int64_t m_tcpPktDebugedSubTotal2;

	// gotPacket() is a callback function of pcap_loop()
	// user - is a pointer to Sniffer object reinterpreted as u_char*
	// header and packet comes from libpcap
	friend void gotPacket(u_char* t_user, const struct pcap_pkthdr* t_header, const u_char* t_packet);
	size_t hash_c_string(const char* p, const size_t s, const size_t prime);
	int m_snifferEndReason;
public:
	Sniffer();
	// constructs a Sniffer object with the parameters taken from the configuration file
	~Sniffer();

	void startCapture();
	void stopCapture();
	void aggregateSessions();
	void writeStatLog();
	int getSnifferEndReason() const;
};

#endif /* SNIFFER_H_ */

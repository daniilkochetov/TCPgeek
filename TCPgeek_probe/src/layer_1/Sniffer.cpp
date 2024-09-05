/*
 *	Sniffer.cpp
 *
 *  Created on: Mar 28, 2022
 *	Last modified on: June 19, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : Sniffer - Main class for capturing.
 *					Implements libpcap functionality. It defines the way to start/stop capture and initiate each packet processing.
 *					This class instantiates TcpPacket and TcpSessions objects.
 *				  Layer 1 - raw data nutrition and its transformation to the
 *				  	universal data objects that can be used for further analysis.
 */

#include "layer_1/Sniffer.h"


Sniffer::Sniffer() {

	log4cpp::Category& logRoot = log4cpp::Category::getRoot();

	try {
		m_statWriter = new StatWriter();
	} catch (std::exception& e) {
		logRoot.fatal("Exception when initializing statistics writer:\n     %s\nExitting.", e.what());
		exit(EXIT_FAILURE);
	}

	//****GETTING READY FOR CAPTURING

	char errbuf[PCAP_ERRBUF_SIZE];
	//try open source as a file first
	m_isOffline = true;
	m_handle = pcap_open_offline(ProgramProperties::getSource().c_str(), errbuf);
	if (m_handle == NULL) {
		// open source as inbound device for live capturing
		// no promiscuous mode, read buffer timeout is 100ms
//		m_handle = pcap_open_live(t_source, MAX_PACKET_LEN, 1, 2000, errbuf);
		m_handle = pcap_create(ProgramProperties::getSource().c_str(), errbuf);
		if(m_handle==NULL) {
			logRoot.fatal("Couldn't create handle for file/device: %s.\n", errbuf);
			exit(EXIT_FAILURE);
		}
	    if((pcap_set_buffer_size(m_handle, ProgramProperties::getPcapBufferSize()))!=0) {
	    	logRoot.fatal("Couldn't set buffer size for %s: %s.\n", ProgramProperties::getSource().c_str(), errbuf);
	    	exit(EXIT_FAILURE);
	    }
	    if((pcap_set_promisc(m_handle, ProgramProperties::isPromiscuous()))!=0) {
	    	logRoot.fatal("Couldn't set promiscuous mode for %s: %s.\n", ProgramProperties::getSource().c_str(), errbuf);
	    	exit(EXIT_FAILURE);
	    }
	    if((pcap_set_timeout(m_handle, ProgramProperties::getPcapBufferTimeout()))!=0) {
	    	logRoot.fatal("Couldn't set timeout for %s: %s.\n", ProgramProperties::getSource().c_str(), errbuf);
	    	exit(EXIT_FAILURE);
	    }

	    if((pcap_set_snaplen(m_handle, MAX_PACKET_LEN))!=0) {
	       	logRoot.fatal("Couldn't set buffer size for %s: %s.\n", ProgramProperties::getSource().c_str(), errbuf);
	       	exit(EXIT_FAILURE);
	    }
	    if ((pcap_activate(m_handle)) != 0) {
	    	logRoot.fatal("Couldn't activate %s: %s.\n", ProgramProperties::getSource().c_str(), errbuf);
	    	exit(EXIT_FAILURE);
	    }

		m_isOffline = false;
		if (m_handle == NULL) {
			logRoot.fatal("Couldn't open file/device %s: %s.\n", ProgramProperties::getSource().c_str(), errbuf);
			exit(EXIT_FAILURE);
		}
	}
	//compiling bpf filter string
	if (pcap_compile(m_handle, &m_bpf, ProgramProperties::getBpfExpression().c_str(), 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
		logRoot.fatal("Couldn't parse filter %s: %s\n",
						ProgramProperties::getBpfExpression().c_str(), pcap_geterr(m_handle));
		pcap_close(m_handle);
		exit(EXIT_FAILURE);
	}
	//applying the filter
	if (pcap_setfilter(m_handle, &m_bpf) == PCAP_ERROR) {
		logRoot.fatal("Couldn't install filter %s: %s\n",
				ProgramProperties::getBpfExpression().c_str(), pcap_geterr(m_handle));
		pcap_freecode(&m_bpf);
		pcap_close(m_handle);
		exit(EXIT_FAILURE);
	}
	//determining link type
	m_linkType = pcap_datalink(m_handle);
	if (m_linkType != DLT_EN10MB && m_linkType != DLT_LINUX_SLL) {
		logRoot.fatal("Link header type %d is unknown. See https://www.tcpdump.org/linktypes.html for details.\n", m_linkType);
		pcap_freecode(&m_bpf);
		pcap_close(m_handle);
		exit(EXIT_FAILURE);
	}

	m_pcapStat = (pcap_stat*) malloc(sizeof(struct pcap_stat));

	//****INITIALIZING OTHER MEMEBERS****

	m_knownPorts = new KnownPorts();
	try {
		m_localSubnets = new LocalSubnets();
	} catch (std::exception& e) {
		logRoot.fatal("Exception when initializing local subnets:\n     %s\nExitting.", e.what());
		pcap_freecode(&m_bpf);
		pcap_close(m_handle);
		exit(EXIT_FAILURE);
	}
	m_sessionsStatQueue = new SafeQueue<StatRecord>();
	m_tcpSessions = new TcpSessions(m_sessionsStatQueue);
	m_udpSessions = new UdpSessions(m_sessionsStatQueue);
	m_debugPacketInfo = new char[256];
	log4cpp::Category& logPacket = log4cpp::Category::getInstance(std::string("packetLog"));
	if (logPacket.getPriority() == log4cpp::Priority::DEBUG) {
		logRoot.warn("Debug mode for each packet is set on 'packetLog' logger, processing will take additional time");
		m_isDebugPacketOn = true;
	} else {
		m_isDebugPacketOn = false;
	}
	m_identifiedSequenceGap = new TcpSequenceGap(0, 0);
	//m_packetDedupRingQueue = new PacketDedupRingQueue(t_dedupMaxSize);
	//self monitoring statistics
	m_pktProcessingCyclesSubTotal = 0;
	m_pktsProcessedSubTotal = 0;
	m_tcpPktDebugCpuCyclesSubTotal0 = 0;
	m_tcpPktDebugedSubTotal0 = 0;
	m_tcpPktDebugCpuCyclesSubTotal1 = 0;
	m_tcpPktDebugedSubTotal1 = 0;
	m_tcpPktDebugCpuCyclesSubTotal2 = 0;
	m_tcpPktDebugedSubTotal2 = 0;
	m_ps_drop_prev = 0;
	m_snifferEndReason = 0;
}

Sniffer::~Sniffer() {
	log4cpp::Category& logRoot = log4cpp::Category::getRoot();

	if (m_handle != NULL ) {
		pcap_freecode(&m_bpf);
		pcap_close(m_handle);
	} else logRoot.warn("PCAP handle is NULL, can't close it");

	logRoot.info("Sniffer has been gracefully shut");
	if (m_isDebugPacketOn) {
		log4cpp::Category& logPacket = log4cpp::Category::getInstance(std::string("packetLog"));
		logPacket.info("Alright then");
		logPacket.info("***********************************************************");
	}

	delete m_localSubnets;
	delete m_statWriter;
	delete m_knownPorts;
	delete m_tcpSessions;
	delete m_udpSessions;
	delete m_sessionsStatQueue;
	delete[] m_debugPacketInfo;
	delete m_identifiedSequenceGap;
}

/*
 * Sniffer::gotPacket is a friend void function that shares the same pointer format with an ordinary C function.
 * That is why it is fully compatible with pcap_loop(...) and can have access to all members of Sniffer object.
 * Pointer to the sniffer object passed as another argument of pcap_loop(...)
 * Ideas taken from here: https://www.newty.de/fpt/callback.html and https://stackoverflow.com/questions/34235959/callback-method-in-pcap-loop
 */
void gotPacket(u_char* t_user, const struct pcap_pkthdr *t_header, const u_char *t_packet) {
	//this method is invoked every time new packet captured with the main thread
	u_int64_t startCycles, endCycles, gotPacketCycles;
	PacketProcessingResultEnum packetProcessingResultEnum;
	TcpSessionUpdateResult tcpSessionUpdateResult;
	UdpSessionUpdateResultEnum  udpSessionUpdateResultEnum = UdpSessionUpdateResultEnum::VOID;


	startCycles = SelfMonitor::getCpuTicks();

	Sniffer *sniffer=reinterpret_cast<Sniffer *>(t_user);

	packetProcessingResultEnum = sniffer->m_newPacket.setPacketFromRaw(t_header, t_packet, sniffer->m_linkType);

	switch (packetProcessingResultEnum) {
		case PacketProcessingResultEnum::GOOD_TCP:
			tcpSessionUpdateResult = sniffer->m_tcpSessions->update(&sniffer->m_newPacket);
			//updating m_tcpSessions map: update existing TCP session or create a new one
			//in tcpSessionUpdateResult it updates only those fields, that couldn't be obtained here
			//!DEBUG
			{
				std::lock_guard<std::mutex> guard(sniffer->m_processingPerformanceMutex);
				if(tcpSessionUpdateResult.debugCpuCycles0 > 0) { //check if the observable procedure happened
					sniffer->m_tcpPktDebugedSubTotal0++;
					sniffer->m_tcpPktDebugCpuCyclesSubTotal0 += tcpSessionUpdateResult.debugCpuCycles0;
				}
				if(tcpSessionUpdateResult.debugCpuCycles1 > 0) { //check if the observable procedure happened
					sniffer->m_tcpPktDebugedSubTotal1++;
					sniffer->m_tcpPktDebugCpuCyclesSubTotal1 += tcpSessionUpdateResult.debugCpuCycles1;
				}
				if(tcpSessionUpdateResult.debugCpuCycles2 > 0) { //check if the observable procedure happened
					sniffer->m_tcpPktDebugedSubTotal2++;
					sniffer->m_tcpPktDebugCpuCyclesSubTotal2 += tcpSessionUpdateResult.debugCpuCycles2;
				}
			}
			//------
			break;
		case PacketProcessingResultEnum::GOOD_UDP:
			udpSessionUpdateResultEnum = sniffer->m_udpSessions->update(&sniffer->m_newPacket);
			//updating m_udpSessions map: update existing UDP session or create a new one
			break;
		default:
			tcpSessionUpdateResult.tcpSessionProcessingResultEnum = TcpSessionProcessingResultEnum::VOID;
			tcpSessionUpdateResult.seqGapEnd = 0;
			tcpSessionUpdateResult.seqGapStart = 0;
			break;
	}

	if (sniffer->m_isDebugPacketOn) {

		PacketStatRecord packetStatRecord(sniffer->m_newPacket, packetProcessingResultEnum, tcpSessionUpdateResult, udpSessionUpdateResultEnum);
		sniffer->m_packetStatQueue.enqueue(packetStatRecord);
		//DEBUG
		//if (sniffer->m_pktsProcessedSubTotal == 10) {
		//	printf("stop");
		//}
	}

	endCycles = SelfMonitor::getCpuTicks();
	gotPacketCycles = endCycles - startCycles;
	{
		std::lock_guard<std::mutex> guard(sniffer->m_processingPerformanceMutex);
		sniffer->m_pktsProcessedSubTotal++;
		sniffer->m_pktProcessingCyclesSubTotal += gotPacketCycles;//duration_nsec;
	}

}

void Sniffer::startCapture() {

	int pcap_res;

	//log4cpp::Category& logRoot = log4cpp::Category::getRoot();
	//starting capture
	pcap_res = pcap_loop(m_handle, 0, gotPacket, reinterpret_cast<u_char *>(this));
	if (m_snifferEndReason == 0) m_snifferEndReason = pcap_res;
}

void Sniffer::stopCapture() {

	log4cpp::Category& logRoot = log4cpp::Category::getRoot();

	std::size_t numberOfTcpSessions = m_tcpSessions->size();
	std::size_t numberOfUdpSessions = m_udpSessions->size();
	logRoot.info("Stopping capture with %d TCP sessions and %d UDP on monitoring", numberOfTcpSessions, numberOfUdpSessions);

	//write stat records accumulated in _statQueue to the log
	uint32_t aggregatedTcpSessions = m_tcpSessions->finalStatCalculation();
	uint32_t aggregatedUdpSessions = m_udpSessions->finalStatCalculation();
	logRoot.info("%d idle TCP sessions were aggregated and erased", aggregatedTcpSessions);
	logRoot.info("%d idle UDP sessions were aggregated and erased", aggregatedUdpSessions);
	writeStatLog();

	if (!m_isOffline) {
		pcap_stats(m_handle, m_pcapStat);
		logRoot.info("%" PRIu32 " packets has been received", m_pcapStat->ps_recv);
		logRoot.info("%" PRIu32 " packets were dropped at the interface", m_pcapStat->ps_ifdrop);
		logRoot.info("%" PRIu32 " packets were dropped at the OS buffer", m_pcapStat->ps_drop);
	}
	if (m_handle != NULL ) {
		pcap_breakloop(m_handle);
	} else logRoot.warn("PCAP handle is NULL, can't stop it");
	if (&m_bpf != NULL ) pcap_freecode(&m_bpf);
		else logRoot.warn("BPF is NULL, can't free its content");
	free(m_pcapStat);

}

void Sniffer::aggregateSessions() {
	//this method is invoked from snifferControl thread running in parallel with main thread that capturing the packets

	//performance self assessment
	u_int64_t startCycles, endCycles, aggrCycles;
	u_int64_t avgPktProcessingCycles = 0;
	u_int64_t pktsProcessedSubTotal;
	u_int64_t avgTcpPktDebug0Cycles = 0;
	u_int64_t tcpPktDebuggedSubTotal0;
	u_int64_t avgTcpPktDebug1Cycles = 0;
	u_int64_t tcpPktDebuggedSubTotal1;
	u_int64_t avgTcpPktDebug2Cycles = 0;
	u_int64_t tcpPktDebuggedSubTotal2;
	u_int32_t droppedByOS = 0;

	startCycles = SelfMonitor::getCpuTicksStart();

	log4cpp::Category& logRoot = log4cpp::Category::getRoot();

	{
		std::lock_guard<std::mutex> guard(m_processingPerformanceMutex);
		//!DEBUG
		tcpPktDebuggedSubTotal0 = m_tcpPktDebugedSubTotal0;
		if (m_tcpPktDebugedSubTotal0 > 0)
			avgTcpPktDebug0Cycles = m_tcpPktDebugCpuCyclesSubTotal0 / m_tcpPktDebugedSubTotal0;
		m_tcpPktDebugCpuCyclesSubTotal0 = 0;
		m_tcpPktDebugedSubTotal0 = 0;

		tcpPktDebuggedSubTotal1 = m_tcpPktDebugedSubTotal1;
		if (m_tcpPktDebugedSubTotal1 > 0)
			avgTcpPktDebug1Cycles = m_tcpPktDebugCpuCyclesSubTotal1 / m_tcpPktDebugedSubTotal1;
		m_tcpPktDebugCpuCyclesSubTotal1 = 0;
		m_tcpPktDebugedSubTotal1 = 0;

		tcpPktDebuggedSubTotal2 = m_tcpPktDebugedSubTotal2;
		if (m_tcpPktDebugedSubTotal2 > 0)
			avgTcpPktDebug2Cycles = m_tcpPktDebugCpuCyclesSubTotal2 / m_tcpPktDebugedSubTotal2;
		m_tcpPktDebugCpuCyclesSubTotal2 = 0;
		m_tcpPktDebugedSubTotal2 = 0;
		//-------
		pktsProcessedSubTotal = m_pktsProcessedSubTotal;
		if (m_pktsProcessedSubTotal > 0)
			avgPktProcessingCycles = m_pktProcessingCyclesSubTotal / m_pktsProcessedSubTotal;
		m_pktProcessingCyclesSubTotal = 0;
		m_pktsProcessedSubTotal = 0;
	}

	if (m_tcpSessions->size() >= ProgramProperties::getMaxTcpSessions()) {
		logRoot.warn("Maximum of %" PRIu64 " simultaneously monitored TCP Sessions "
				"has been reached during last interval! New sessions can't be monitored.", ProgramProperties::getMaxTcpSessions());
	}
	logRoot.info("Active TCP Sessions count is %" PRIu64 ", active UDP Sessions count is %" PRIu64
					", average cycles packet processing is %" PRIu64 ", %" PRIu64 " packets were analyzed",
						m_tcpSessions->size(), m_udpSessions->size(), avgPktProcessingCycles, pktsProcessedSubTotal);
	//!DEBUG
	logRoot.debug("Statistical records to write: %" PRIu64, m_sessionsStatQueue->size());
	logRoot.debug("Average TCP packet debug0 cycles is %" PRIu64 ", %" PRIu64 " packets were analyzed", avgTcpPktDebug0Cycles, tcpPktDebuggedSubTotal0);
	logRoot.debug("Average TCP packet debug1 cycles is %" PRIu64 ", %" PRIu64 " packets were analyzed", avgTcpPktDebug1Cycles, tcpPktDebuggedSubTotal1);
	logRoot.debug("Average TCP packet debug2 cycles is %" PRIu64 ", %" PRIu64 " packets were analyzed", avgTcpPktDebug2Cycles, tcpPktDebuggedSubTotal2);
	//------
	logRoot.info("CPU usage %f\%, Virtual Memory Usage %dKb, Physical Memory Usage %" PRIu32 "Kb",
					m_selfMonitor.getCpuUsagePecentage(), m_selfMonitor.getVirtualMemoryKb(), m_selfMonitor.getPhysicalMemoryKb());
	if (!m_isOffline) {
		pcap_stats(m_handle, m_pcapStat);
		droppedByOS = m_pcapStat->ps_drop - m_ps_drop_prev;
		logRoot.info("In total libpcap captured %" PRIu32 " packets, %" PRIu32
						" packets were dropped at the interface, %" PRIu32 " packets were dropped at the OS buffer",
					m_pcapStat->ps_recv, m_pcapStat->ps_ifdrop, droppedByOS);
		uint32_t erasedSessions = m_tcpSessions->cleanIdleSessions();
		logRoot.info("%d idle TCP sessions were aggregated and erased", erasedSessions);
		erasedSessions = m_udpSessions->cleanIdleSessions();
		logRoot.info("%d idle UDP sessions were aggregated and erased", erasedSessions);
		m_ps_drop_prev = m_pcapStat->ps_drop;
	}

	if (m_selfMonitor.getPhysicalMemoryKb() >= ProgramProperties::getMaxMemoryUsageKb()) {
		m_snifferEndReason = 167;
		logRoot.info("Stopping capture due to high memory usage");
		kill(getpid(),SIGINT);
	}

	writeStatLog();

	if (ProgramProperties::doRestartOnDrops() && (droppedByOS > 0)) {
		m_snifferEndReason = 166;
		logRoot.info("Stopping capture due to high OS drops");
		kill(getpid(),SIGINT);
	}

	endCycles = SelfMonitor::getCpuTicksEnd();
	aggrCycles = endCycles - startCycles;
	logRoot.debug("Aggregation completed in %" PRIu64 " cycles", aggrCycles);
}

void Sniffer::writeStatLog() {
	//write stat records accumulated in _statQueue to the log
	m_statWriter->writeStat(m_sessionsStatQueue);
	if (m_isDebugPacketOn) {
		m_pcktStatRecordLogger.logPacketStatRecords(m_packetStatQueue);
	}
}

size_t Sniffer::hash_c_string(const char* p, const size_t s, const size_t prime) {
    size_t result = prime;
    for (size_t i = 0; i < s; ++i) {
        result = p[i] + (result * 31);
    }
    return result;
}

int Sniffer::getSnifferEndReason() const {
	return m_snifferEndReason;
}

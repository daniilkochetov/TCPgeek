/*
 *	TCPgeek_rt.h
 *
 *	Created on: Mar 28, 2022
 *	Last modified on: Mar 28, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TcpPacket - Describes necessary fields of captured TCP packet, the
 *					way of their assignment from the captured network frame and logging
 *					debug information when necessary
 *				  Layer 1 - raw data nutrition and its transformation to the
 *				  universal data objects that can be used for further analysis.
 */


#ifndef PACKET_H_
#define PACKET_H_

#include <arpa/inet.h> // for inet_ntop
#include <pcap.h> // for pcap_pkthdr

#include <log4cpp/Category.hh> // for logging capabilities
#include "layer_1/PacketProcessingResultEnum.h"
#include "layer_1/networkHeaders.h"




class PacketStatRecord;
class Packet {

private:
	//common fields for all protocols
	struct timeval		m_ts;
	u_int64_t	 		m_timestamp_usec_full; //full timestamp in microseconds
	u_int32_t			m_totalLen;
	u_int32_t	 		m_payloadLen;
	//IP specific fields
	u_char				m_ipProtocol;
	in_addr				m_srcIpRaw, m_dstIpRaw; //32 bits or u_int32
	u_int64_t			m_dupId;
	//TCP/UDP specific fields
	u_short				m_srcPort, m_dstPort; //16 bits
	//TCP specific fields
	bool	 			m_synFlag, m_pshFlag, m_finFlag, m_rstFlag, m_ackFlag;
	u_int32_t 			m_sequenceNumber, m_nextSequenceNumber, m_ackNumber;

	PacketProcessingResultEnum setIpPacketFromRaw(const IpHeader *t_ipHdrPtr);
	PacketProcessingResultEnum setTcpPacketFromRaw(const TcpHeader *t_tcpHdrPtr);
	PacketProcessingResultEnum setUdpPacketFromRaw(UdpHeader *t_tcpHdrPtr);

public:
	Packet();
	Packet(const Packet &t_tcpPacket);
	~Packet();


	Packet& operator = (const Packet other) {
		m_ts = other.m_ts;
		m_timestamp_usec_full = other.m_timestamp_usec_full;
		m_totalLen = other.m_totalLen;
		m_payloadLen = other.m_payloadLen;
		m_ipProtocol = other.m_ipProtocol;
		m_srcIpRaw = other.m_srcIpRaw;
		m_dstIpRaw = other.m_dstIpRaw;
		m_dupId = other.m_dupId;
		m_srcPort = other.m_srcPort;
		m_dstPort = other.m_dstPort;
		m_synFlag = other.m_synFlag;
		m_pshFlag = other.m_pshFlag;
		m_finFlag = other.m_finFlag;
		m_rstFlag = other.m_rstFlag;
		m_ackFlag = other.m_ackFlag;
		m_sequenceNumber = other.m_sequenceNumber;
		m_nextSequenceNumber = other.m_nextSequenceNumber;
		m_ackNumber = other.m_ackNumber;
		return *this;
	}

	//fills TcpPacket object fields with data extracted from raw packet
	//returns status of execution
	PacketProcessingResultEnum setPacketFromRaw(const struct pcap_pkthdr *t_header, const u_char *t_packet, const int t_linkType);

	PacketStatRecord getDebugPacketInfo();

	//two non-trivial getters
	int getTcpHeaderLength(const TcpHeader* t_tcpHeader) const;
	u_char getIpHeaderLength(const IpHeader* t_ipHeader) const;

	const std::string getPacketDescriptionStr() const;

	u_int32_t getAckNumber() const;
	bool isFinFlag() const;
	u_int32_t getNextSequenceNumber() const;
	u_int32_t getPayloadlen() const;
	bool isPshFlag() const;
	bool isRstFlag() const;
	u_int32_t getSequenceNumber() const;
	bool isSynFlag() const;
	uint64_t getTimestampUsecFull() const;
	const struct timeval& getTs() const;
	u_short getIpId() const;
	u_char getIpTtl() const;
	u_int64_t getDupId() const;
	in_addr getDstIpRaw() const;
	u_short getDstPort() const;
	in_addr getSrcIpRaw() const;
	u_short getSrcPort() const;
	bool isAckFlag() const;
	u_int32_t getTotalLen() const;
	u_char getIpProtocol() const;
};

#endif /* PACKET_H_ */

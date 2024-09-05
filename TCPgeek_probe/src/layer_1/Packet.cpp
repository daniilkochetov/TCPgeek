/*
 *	TCPgeek_rt.cpp
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


#include "layer_1/Packet.h"

Packet::Packet() : m_timestamp_usec_full {0},
						m_totalLen {0},
						m_payloadLen {0},
						m_ipProtocol {0},
						m_dupId {0},
						m_srcPort {0},
						m_dstPort {0},
						m_synFlag {false},
						m_pshFlag {false},
						m_finFlag {false},
						m_rstFlag {false},
						m_ackFlag {false},
						m_sequenceNumber {0},
						m_nextSequenceNumber {0},
						m_ackNumber {0} {
	m_ts.tv_sec = 0;
	m_ts.tv_usec = 0;
	m_srcIpRaw.s_addr = 0;
	m_dstIpRaw.s_addr = 0;
}

Packet::Packet(const Packet &t_tcpPacket) {
    this->m_srcPort = t_tcpPacket.m_srcPort;
    this->m_dstPort = t_tcpPacket.m_dstPort;
    this->m_srcIpRaw = t_tcpPacket.m_srcIpRaw;
    this->m_dstIpRaw = t_tcpPacket.m_dstIpRaw;
    this->m_ts = t_tcpPacket.m_ts;
    this->m_timestamp_usec_full = t_tcpPacket.m_timestamp_usec_full;
    this->m_synFlag = t_tcpPacket.m_synFlag;
    this->m_pshFlag = t_tcpPacket.m_pshFlag;
    this->m_finFlag = t_tcpPacket.m_finFlag;
    this->m_rstFlag = t_tcpPacket.m_rstFlag;
    this->m_ackFlag = t_tcpPacket.m_ackFlag;
    this->m_sequenceNumber = t_tcpPacket.m_sequenceNumber;
    this->m_nextSequenceNumber = t_tcpPacket.m_nextSequenceNumber;
    this->m_ackNumber = t_tcpPacket.m_ackNumber;
    this->m_totalLen = t_tcpPacket.m_totalLen;
    this->m_payloadLen = t_tcpPacket.m_payloadLen;
    this->m_dupId = t_tcpPacket.m_dupId;
    this->m_ipProtocol = t_tcpPacket.m_ipProtocol;
}


Packet::~Packet() {
	//std::cout << "TCP packet: " << _sessionKey << " destroyed" << std::endl;
}

PacketProcessingResultEnum Packet::setPacketFromRaw(const struct pcap_pkthdr *t_header, const u_char *t_packet, const int t_linkType) {

	//EthernetHeader* ethernetHeader;
	u_char etherHeaderLen;
	u_short etherType;
	PacketProcessingResultEnum result;

	//SET TIMESTAMP AND TOTAL PACKET LENGTH FROM LIBPCAP HEADER
	m_ts = t_header->ts;
	m_timestamp_usec_full = (uint64_t) t_header->ts.tv_sec * 1000000L + t_header->ts.tv_usec;
	m_totalLen = t_header->len;

	//PARSING ETHERNET HEADER

	if (t_linkType == DLT_EN10MB) {
		EthernetHeader* ethernetHeader = (EthernetHeader*) t_packet;
		etherType = ntohs(ethernetHeader->protocolType);
		etherHeaderLen = ETHER_HDR_LEN;
		//m_totalLen += 4; // +FCS
		//if (m_totalLen < 64) m_totalLen = 64;
	} else if (t_linkType == DLT_LINUX_SLL) {
		EthernetSLLHeader* ethernetSllHeader;
		ethernetSllHeader = (EthernetSLLHeader*) t_packet;
		etherType = ntohs(ethernetSllHeader->protocolType);
		etherHeaderLen = ETH_SLL_HDR_LEN;
		//m_totalLen += 4; // +FCS
		//if (m_totalLen < 64) m_totalLen = 64;
	} else {
		return PacketProcessingResultEnum::UNKNOWN_LINK_TYPE;
	}

	//PARSING L2
	if (etherType == ETHERTYPE_VLAN) {
		VlanHeader* vlanHdr;
		vlanHdr =  (VlanHeader*) (t_packet + etherHeaderLen - sizeof(u_short));
		etherType = ntohs(vlanHdr->protocolType);
		etherHeaderLen += VLAN_TAG_LEN;
	}

	if (etherType == ETHERTYPE_IP) {
		result = setIpPacketFromRaw((IpHeader*)(t_packet + etherHeaderLen));
	} else {
		//No way to understand source and destination locations, hence ignored
		result = PacketProcessingResultEnum::NOT_IP_PACKET;
	}
	return result;
}

PacketProcessingResultEnum Packet::setIpPacketFromRaw(const IpHeader *t_ipHdrPtr) {

	PacketProcessingResultEnum result;
	u_char ipHeaderSize;

	/*PARSING IP HEADER*/

	ipHeaderSize = getIpHeaderLength(t_ipHdrPtr);
	if (ipHeaderSize < 20) {
		result = PacketProcessingResultEnum::BAD_IP_HEADER_LEN;
		return result;
	}
	m_srcIpRaw = t_ipHdrPtr->ipSourceAddress;
	m_dstIpRaw = t_ipHdrPtr->ipDestinationAddress;
	m_dupId = t_ipHdrPtr->ipId << 16;
	m_payloadLen = ntohs(t_ipHdrPtr->ipLenght) - ipHeaderSize;
	m_ipProtocol = t_ipHdrPtr->ipProtocol;
	switch (m_ipProtocol) {
		case IPPROTO_TCP:
			result = setTcpPacketFromRaw((TcpHeader*)((u_char*) t_ipHdrPtr + ipHeaderSize));
			break;
		case IPPROTO_UDP:
			result = setUdpPacketFromRaw((UdpHeader*)((u_char*) t_ipHdrPtr + ipHeaderSize));
			break;
		default:
			result = PacketProcessingResultEnum::UNKNOWN_L3_TYPE;
			break;
	}
	return result;
}

PacketProcessingResultEnum Packet::setUdpPacketFromRaw(UdpHeader* t_udpHdrPtr) {
	u_short   length;
	length = ntohs(t_udpHdrPtr->length);
	if (length < 8) {
		return PacketProcessingResultEnum::BAD_UDP_LEN;
	}
	m_srcPort = ntohs(t_udpHdrPtr->udpSourcePort);
	m_dstPort = ntohs(t_udpHdrPtr->udpDestinationPort);
	m_dupId = (m_dupId + t_udpHdrPtr->udpChecksum) << 32;
	m_payloadLen = length - 8;
	u_int32_t dupIdAddon = 0;
	const u_char *payloadBytesPtr = (u_char *)t_udpHdrPtr + 8;
	for (u_int32_t i = 0; i < m_payloadLen; i++) {
		dupIdAddon = dupIdAddon << 8;
		dupIdAddon = dupIdAddon + *payloadBytesPtr;
		payloadBytesPtr = payloadBytesPtr + 1;
		if (i == 3) break;
	}
	m_dupId += dupIdAddon;

	return PacketProcessingResultEnum::GOOD_UDP;
}

PacketProcessingResultEnum Packet::setTcpPacketFromRaw(const TcpHeader* t_tcpHdrPtr) {
	u_int32_t tcpHeaderSize;

	tcpHeaderSize = getTcpHeaderLength(t_tcpHdrPtr);
	if (tcpHeaderSize < 20) {
		return PacketProcessingResultEnum::BAD_TCP_HEADER_LEN;
	}
	m_srcPort = ntohs(t_tcpHdrPtr->tcpSourcePort);
	m_dstPort = ntohs(t_tcpHdrPtr->tcpDestinationPort);
	//parsing TCP flags
	m_finFlag = t_tcpHdrPtr->tcpFlags & TH_FIN;
	m_synFlag = t_tcpHdrPtr->tcpFlags & TH_SYN;
	m_rstFlag = t_tcpHdrPtr->tcpFlags & TH_RST;
	m_pshFlag = t_tcpHdrPtr->tcpFlags & TH_PUSH;
	m_ackFlag = t_tcpHdrPtr->tcpFlags & TH_ACK;

	m_sequenceNumber = ntohl(t_tcpHdrPtr->tcpSequenceNumber);
	m_ackNumber = ntohl(t_tcpHdrPtr->tcpAckNumber);

	/* IDENTIFYING GENERAL PARAMETERS*/
	m_dupId = (m_dupId + t_tcpHdrPtr->tcpChecksum) << 32;
	m_dupId += m_sequenceNumber;

	m_payloadLen -= tcpHeaderSize;
	if (m_synFlag){
		m_nextSequenceNumber = m_sequenceNumber + 1;
	} else {
		m_nextSequenceNumber = m_sequenceNumber + m_payloadLen;
	}
	return PacketProcessingResultEnum::GOOD_TCP;
}

const std::string Packet::getPacketDescriptionStr() const {
		std::string result;
		char srcIpStr[INET_ADDRSTRLEN];
		char dstIpStr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(m_srcIpRaw), srcIpStr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(m_dstIpRaw), dstIpStr, INET_ADDRSTRLEN);
		result = std::string(srcIpStr) + "." + std::to_string(m_srcPort) + " -> " + std::string(dstIpStr) + "." + std::to_string(m_dstPort);

		switch (m_ipProtocol) {
			case IPPROTO_TCP:
				result = "TCP;" + result;
				break;
			case IPPROTO_UDP:
				result = "UDP;" + result;
				break;
			default:

				break;
		}
		return result;
}

int Packet::getTcpHeaderLength(const TcpHeader* t_tcpHeader) const {
	return ((t_tcpHeader->tcpDataOffsetAndReseve & 0xf0) >> 4) * 4;
}

u_char Packet::getIpHeaderLength(const IpHeader* t_ipHeader) const {
	return (t_ipHeader->ipVersionAndLenght & 0x0f) * 4;
}

u_int32_t Packet::getAckNumber() const {
	return m_ackNumber;
}

bool Packet::isFinFlag() const {
	return m_finFlag;
}

u_int32_t Packet::getNextSequenceNumber() const {
	return m_nextSequenceNumber;
}

u_int32_t Packet::getPayloadlen() const {
	return m_payloadLen;
}

bool Packet::isPshFlag() const {
	return m_pshFlag;
}

bool Packet::isRstFlag() const {
	return m_rstFlag;
}

u_int32_t Packet::getSequenceNumber() const {
	return m_sequenceNumber;
}

bool Packet::isSynFlag() const {
	return m_synFlag;
}

const struct timeval& Packet::getTs() const {
	return m_ts;
}

u_int64_t Packet::getTimestampUsecFull() const {
	return m_timestamp_usec_full;
}

u_int64_t Packet::getDupId() const {
	return m_dupId;
}

in_addr Packet::getDstIpRaw() const {
	return m_dstIpRaw;
}

u_short Packet::getDstPort() const {
	return m_dstPort;
}

in_addr Packet::getSrcIpRaw() const {
	return m_srcIpRaw;
}

u_int32_t Packet::getTotalLen() const {
	return m_totalLen;
}

bool Packet::isAckFlag() const {
	return m_ackFlag;
}

u_short Packet::getSrcPort() const {
	return m_srcPort;
}

u_char Packet::getIpProtocol() const {
	return m_ipProtocol;
}


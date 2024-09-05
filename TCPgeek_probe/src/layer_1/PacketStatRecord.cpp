/*
 *	PacketStatRecord.cpp
 *
 *  Created on: Mar 28, 2022
 *	Last modified on: Mar 28, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : PacketStatRecord - Describes single statistical record of
 *					TCP packet. Includes TCP/IP packet fields and values calculated
 *					after the TCP session update: Out-of-order/Retransmit/Keepalive
 *				  Layer 2 - Analysis and logging of data structured at Layer 1
 */

#include "layer_1/PacketStatRecord.h"


PacketStatRecord::PacketStatRecord() {
	m_udpSessionUpdateResultEnum = UdpSessionUpdateResultEnum::VOID;
	m_packetProcessingResultEnum = PacketProcessingResultEnum::UNKNOWN_LINK_TYPE;
}

PacketStatRecord::PacketStatRecord(const Packet t_packet,
								   const PacketProcessingResultEnum t_packetProcessingResultEnum,
								   const TcpSessionUpdateResult t_sessionUpdateResult,
								   const UdpSessionUpdateResultEnum  t_udpSessionUpdateResultEnum) {
	m_packet = t_packet;
	m_packetProcessingResultEnum = t_packetProcessingResultEnum;
	m_tcpSessionUpdateResult = t_sessionUpdateResult;
	m_udpSessionUpdateResultEnum = t_udpSessionUpdateResultEnum;

	//TODO: Reduce number of assignments by defining only required fields in this class

}

PacketProcessingResultEnum PacketStatRecord::getPacketProcessingResultEnum() const {
	return m_packetProcessingResultEnum;
}

const TcpSessionUpdateResult PacketStatRecord::getTcpSessionUpdateResult() const {
	return m_tcpSessionUpdateResult;
}

UdpSessionUpdateResultEnum PacketStatRecord::getUdpSessionUpdateResultEnum() const {
	return m_udpSessionUpdateResultEnum;
}

const Packet& PacketStatRecord::getPacket() const {
	return m_packet;
}

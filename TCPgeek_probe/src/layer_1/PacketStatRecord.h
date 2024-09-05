/*
 *	PacketStatRecord.h
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

#ifndef PACKETSTATRECORD_H_
#define PACKETSTATRECORD_H_

#include "layer_1/sessions/TcpUdpSessionKey.h"
#include "layer_1/sessions/TCP/TcpSessionUpdateResult.h"
#include "layer_1/sessions/UDP/UdpSessionUpdateResultEnum.h"
#include "layer_1/Packet.h"
#include "layer_1/PacketProcessingResultEnum.h"


class PacketStatRecord {

private:
	Packet						m_packet; //TODO: Reduce number of assignments by defining only required fields in this class
	/*struct timeval		m_ts;
	u_int32_t			m_totalLen;
	u_int32_t	 		m_payloadLen;
	in_addr				m_srcIpRaw, m_dstIpRaw; //32 bits or u_int32
	u_short				m_srcPort, m_dstPort; //16 bits
	bool	 			m_synFlag, m_pshFlag, m_finFlag, m_rstFlag, m_ackFlag;
	u_int32_t 			m_sequenceNumber, m_nextSequenceNumber, m_ackNumber;*/

	PacketProcessingResultEnum	m_packetProcessingResultEnum;
	TcpSessionUpdateResult 		m_tcpSessionUpdateResult;
	UdpSessionUpdateResultEnum  m_udpSessionUpdateResultEnum;
public:

	//might be invoked only from the main thread of capturing
	//updates single node of std::list that will be put to the SafeQueue<PacketStatRecord> _packetStatQueue
	//and then stored in the log file during tcp sessions aggregation
	PacketStatRecord();
	PacketStatRecord(const Packet t_packet,
					 const PacketProcessingResultEnum t_packetProcessingResult,
					 const TcpSessionUpdateResult t_sessionUpdateResult,
					 const UdpSessionUpdateResultEnum  t_udpSessionUpdateResultEnum);
	PacketProcessingResultEnum getPacketProcessingResultEnum() const;
	const TcpSessionUpdateResult getTcpSessionUpdateResult() const;
	UdpSessionUpdateResultEnum getUdpSessionUpdateResultEnum() const;
	const Packet& getPacket() const;
};

#endif /* PACKETSTATRECORD_H_ */

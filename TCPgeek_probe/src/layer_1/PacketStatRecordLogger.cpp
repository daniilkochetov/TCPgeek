/*
 *	PacketStatRecordLogger.cpp
 *
 *  Created on: Mar 28, 2022
 *	Last modified on: Mar 28, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : PacketStatRecordLogger - Defines the way of logging of
 *					PacketStatRecords taken from packetStatQueue
 *				  Layer 2 - Analysis and logging of data structured at Layer 1
 */

#include "layer_1/PacketStatRecordLogger.h"

void PacketStatRecordLogger::logPacketStatRecords(SafeQueue<PacketStatRecord> &t_packetStatQueue) {
	float usec;

	char timestamp_str[TIMESTAMP_STR_MAX_SIZE];
	char outStr[OUT_STRING_MAX_LEN];
	struct tm *timestamp_tm;
	char tv_usecStr[16];

	strcpy(timestamp_str, "2000-01-01 00:00:00.000000");
	while (t_packetStatQueue.dequeue(m_packetStatRecord)) {

		timestamp_tm = gmtime(&m_packetStatRecord.getPacket().getTs().tv_sec);

		strftime(timestamp_str, sizeof timestamp_str, "%Y-%m-%d %H:%M:%S.", timestamp_tm);
		usec = (float)m_packetStatRecord.getPacket().getTs().tv_usec/(float)1000000;
		snprintf(tv_usecStr, sizeof tv_usecStr, "%f", usec);
		char *newString = tv_usecStr + 2;
		memcpy(timestamp_str+20, newString, 6);
		//strcat(timestamp_str, newString);
		//strncat(timestamp_str, newString, 6);

		log4cpp::Category& logPacket = log4cpp::Category::getInstance(std::string("packetLog"));
		switch(m_packetStatRecord.getPacketProcessingResultEnum()) {
			case PacketProcessingResultEnum::GOOD_TCP:
				getTcpLogString(m_packetStatRecord.getTcpSessionUpdateResult(), outStr);
				logPacket.debug("%s; %s", timestamp_str, outStr);
				break;
			case PacketProcessingResultEnum::GOOD_UDP:
				getUdpLogString(m_packetStatRecord.getUdpSessionUpdateResultEnum(), outStr);
				logPacket.debug("%s; %s", timestamp_str, outStr);
				break;
			case PacketProcessingResultEnum::UNKNOWN_LINK_TYPE:
				logPacket.debug("%s; Unknown link type", timestamp_str);
				continue;
			case PacketProcessingResultEnum::NOT_IP_PACKET:
				logPacket.debug("%s; Not IP packet", timestamp_str);
				continue;
			case PacketProcessingResultEnum::UNKNOWN_L3_TYPE:
				logPacket.debug("%s; Unknown layer 3", timestamp_str);
				continue;
			case PacketProcessingResultEnum::BAD_IP_HEADER_LEN:
				logPacket.debug("%s; Invalid IP header length", timestamp_str);
				continue;
			case PacketProcessingResultEnum::BAD_TCP_HEADER_LEN:
				logPacket.debug("%s; Invalid TCP header length", timestamp_str);
				continue;
			case PacketProcessingResultEnum::BAD_UDP_LEN:
				logPacket.debug("%s; Invalid UDP packet length", timestamp_str);
				continue;
			default:
				logPacket.debug("%s; Really strange packet", timestamp_str);
				break;
		}


	}

}

void PacketStatRecordLogger::getTcpLogString(TcpSessionUpdateResult tcpSessionUpdateResult, char *logString) {
	char tcpFlagsStr[16];
	char sourceIpStr[INET_ADDRSTRLEN];
	char destinationIpStr[INET_ADDRSTRLEN];
	char gapDescriptionString[100];
	in_addr	srcIpRaw, dstIpRaw;

	srcIpRaw = m_packetStatRecord.getPacket().getSrcIpRaw();
	dstIpRaw = m_packetStatRecord.getPacket().getDstIpRaw();
	inet_ntop(AF_INET, &srcIpRaw, sourceIpStr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dstIpRaw, destinationIpStr, INET_ADDRSTRLEN);

	strcpy(tcpFlagsStr,"[.......]");
	if (m_packetStatRecord.getPacket().isFinFlag()) tcpFlagsStr[1]='F';
	if (m_packetStatRecord.getPacket().isSynFlag()) tcpFlagsStr[2]='S';
	if (m_packetStatRecord.getPacket().isRstFlag()) tcpFlagsStr[3]='R';
	if (m_packetStatRecord.getPacket().isPshFlag()) tcpFlagsStr[4]='P';
	if (m_packetStatRecord.getPacket().isAckFlag()) tcpFlagsStr[5]='A';

	snprintf(logString, OUT_STRING_MAX_LEN, "TCP; %s.%d > %s.%d; %s; seq %lu -> %lu; ack %lu; length %d (%d)",
			sourceIpStr, m_packetStatRecord.getPacket().getSrcPort(),
			destinationIpStr, m_packetStatRecord.getPacket().getDstPort(), tcpFlagsStr,
			(unsigned long) m_packetStatRecord.getPacket().getSequenceNumber(),
			(unsigned long) m_packetStatRecord.getPacket().getNextSequenceNumber(),
			(unsigned long) m_packetStatRecord.getPacket().getAckNumber(),
			m_packetStatRecord.getPacket().getPayloadlen(),
			m_packetStatRecord.getPacket().getTotalLen());
	if (tcpSessionUpdateResult.operationStatus == OperationStatusEnum::REQUEST_STARTED) {
		strcat(logString, "; Request Started");
	}
	if (tcpSessionUpdateResult.operationStatus == OperationStatusEnum::RESPONSE_STARTED) {
		strcat(logString, "; Response Started");
	}
	switch(tcpSessionUpdateResult.tcpSessionProcessingResultEnum) {
		case TcpSessionProcessingResultEnum::GOOD_KNOWN:
		break;
		case TcpSessionProcessingResultEnum::VOID:
			strcat(logString, "; Ignored");
			break;
		case TcpSessionProcessingResultEnum::GOOD_NEW:
			strcat(logString, "; New session");
			break;
		case TcpSessionProcessingResultEnum::RETRANSMIT:
			if (tcpSessionUpdateResult.seqGapStart == 0) {
				strcat(logString, "; Retransmit");
			} else {
				snprintf(gapDescriptionString, OUT_STRING_MAX_LEN,	"; Retransmit with %u - %u gap recovery",
							tcpSessionUpdateResult.seqGapStart,	tcpSessionUpdateResult.seqGapEnd);
				strcat(logString, gapDescriptionString);
			}
			break;
		case TcpSessionProcessingResultEnum::DUPLICATE:
			strcat(logString, "; Duplicate");
			break;
		case TcpSessionProcessingResultEnum::NEW_GAP:
			snprintf(gapDescriptionString, OUT_STRING_MAX_LEN, "; Out-of-order - new TCP sequence gap %u - %u",
						tcpSessionUpdateResult.seqGapStart,	tcpSessionUpdateResult.seqGapEnd);
			strcat(logString, gapDescriptionString);
			break;
		case TcpSessionProcessingResultEnum::GAP_RECOVERY:
			snprintf(gapDescriptionString, OUT_STRING_MAX_LEN, "; Out-of-order - recovers TCP sequence gap %u - %u",
						tcpSessionUpdateResult.seqGapStart,	tcpSessionUpdateResult.seqGapEnd);
			strcat(logString, gapDescriptionString);
			break;
		case TcpSessionProcessingResultEnum::KEEPALIVE:
			strcat(logString, "; Keepalive");
			break;
	}
}

void PacketStatRecordLogger::getUdpLogString(UdpSessionUpdateResultEnum udpSessionUpdateResultEnum, char* logString) {
		char sourceIpStr[INET_ADDRSTRLEN];
		char destinationIpStr[INET_ADDRSTRLEN];
		in_addr	srcIpRaw, dstIpRaw;

		srcIpRaw = m_packetStatRecord.getPacket().getSrcIpRaw();
		dstIpRaw = m_packetStatRecord.getPacket().getDstIpRaw();
		inet_ntop(AF_INET, &srcIpRaw, sourceIpStr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &dstIpRaw, destinationIpStr, INET_ADDRSTRLEN);

		snprintf(logString, OUT_STRING_MAX_LEN, "UDP; %s.%d > %s.%d; payload length %d",
				sourceIpStr, m_packetStatRecord.getPacket().getSrcPort(),
				destinationIpStr, m_packetStatRecord.getPacket().getDstPort(),
				m_packetStatRecord.getPacket().getPayloadlen());
		switch(udpSessionUpdateResultEnum) {
			case UdpSessionUpdateResultEnum::GOOD_KNOWN:
			break;
			case UdpSessionUpdateResultEnum::VOID:
				strcat(logString, "; Ignored");
				break;
			case UdpSessionUpdateResultEnum::GOOD_NEW:
				strcat(logString, "; New session");
				break;
			case UdpSessionUpdateResultEnum::DUPLICATE:
				strcat(logString, "; Duplicate");
				break;
		}
}

PacketStatRecordLogger::PacketStatRecordLogger() {
}

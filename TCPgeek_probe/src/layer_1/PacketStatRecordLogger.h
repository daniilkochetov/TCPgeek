/*
 *	PacketStatRecordLogger.h
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

#ifndef PACKETSTATRECORDLOGGER_H_
#define PACKETSTATRECORDLOGGER_H_

//#define TIMESTAMP_STR_MAX_SIZE 64
#define TIMESTAMP_STR_MAX_SIZE 64
#define OUT_STRING_MAX_LEN 256

#include <string.h>

#include <log4cpp/Category.hh> // for logging capabilities

//#include "layer_1/networkHeaders.h" // for TCP and IP network headers format and related constants
//#include "SafeQueue.h" // for statistic records queuing
//#include "layer_2/PacketStatRecord.h"
//#include "layer_1/TcpSessions.h"
#include "layer_1/sessions/TCP/TcpSessionUpdateResult.h"
#include "layer_1/sessions/UDP/UdpSessionUpdateResultEnum.h"
#include "layer_1/networkHeaders.h" // for TCP and IP network headers format and related constants
#include "SafeQueue.h" // for statistic records queuing
#include "layer_1/PacketStatRecord.h"
#include "layer_1/sessions/TCP/TcpSessions.h"
#include "layer_1/OperationStatusEnum.h"



class PacketStatRecordLogger {
private:
	PacketStatRecord m_packetStatRecord;

	void getTcpLogString(TcpSessionUpdateResult tcpSessionUpdateResult, char *logString);
	void getUdpLogString(UdpSessionUpdateResultEnum  udpSessionUpdateResultEnum, char *logString);
public:
	PacketStatRecordLogger();
	void logPacketStatRecords(SafeQueue<PacketStatRecord> &t_packetStatQueue);
	//might be invoked only from the snifferControl thread
	//writes all nodes of the packetStatQueue to the log
};

#endif /* PACKETSTATRECORDLOGGER_H_ */

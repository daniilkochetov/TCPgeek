/*
 *	TcpSessionProcessingResult.h
 *
 *	Created on: May 12, 2023
 *	Last modified on: May 12, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef TCPSESSIONUPDATERESULT_H_
#define TCPSESSIONUPDATERESULT_H_

#include <inttypes.h>

#include "layer_1/OperationStatusEnum.h"

enum class TcpSessionProcessingResultEnum {
			GOOD_NEW,
			GOOD_KNOWN,
			NEW_GAP,
			GAP_RECOVERY,
			RETRANSMIT,
			KEEPALIVE,
			DUPLICATE,
			VOID
};

struct TcpSessionUpdateResult
{
	TcpSessionProcessingResultEnum tcpSessionProcessingResultEnum;
	uint32_t	seqGapStart;
	uint32_t	seqGapEnd;
	uint64_t	debugCpuCycles0 = 0;
	uint64_t	debugCpuCycles1 = 0;
	uint64_t	debugCpuCycles2 = 0;
	OperationStatusEnum operationStatus;

};

#endif /* TCPSESSIONUPDATERESULT_H_ */

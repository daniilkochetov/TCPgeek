/*
 *	PacketProcessingResultEnum.h
 *
 *  Created on: May 12, 2023
 *	Last modified on: May 12, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef PACKETPROCESSINGRESULTENUM_H_
#define PACKETPROCESSINGRESULTENUM_H_



enum class PacketProcessingResultEnum{
			GOOD_TCP,
			GOOD_UDP,
			UNKNOWN_LINK_TYPE, 	//Link type is unknown
			NOT_IP_PACKET, 		//Ethernet type is not IP
			UNKNOWN_L3_TYPE, 	//Ethernet type is unknown
			BAD_IP_HEADER_LEN, 	//Invalid IP header length
			BAD_TCP_HEADER_LEN, //Invalid TCP header length
			BAD_UDP_LEN 	//Invalid TCP header length
} ;



#endif /* PACKETPROCESSINGRESULTENUM_H_ */

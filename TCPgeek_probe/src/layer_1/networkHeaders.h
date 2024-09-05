/*
 *	networkHeaders.h
 *
 *	Created on: Nov 30, 2021
 *	Last modified on: Nov 30, 2021
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : Declares TCP and IP network headers and related constants
 *				  instantiates TcpPacket and TcpSessions objects.
 *				  Layer 1 - raw data nutrition and its transformation to the
 *			      universal data objects that can be used for further analysis.
 */

#ifndef NETWORKHEADERS_H_
#define NETWORKHEADERS_H_

#include <netinet/in.h>
#include <net/ethernet.h>

// maximum bytes per packet
//#define MAX_PACKET_LEN 1518
#define MAX_PACKET_LEN 128

// Ethernet header are always exactly 14 bytes
#define ETH_SLL_HDR_LEN 16

// IP_HEADER_FLAGS
#define IP_RF 0x8000            // reserved fragment flag
#define IP_DF 0x4000            // don't fragment flag
#define IP_MF 0x2000            // more fragments flag
#define IP_OFFMASK 0x1fff       // mask for fragmenting bits

// TCP_HEADER_FLAGS
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

#define VLAN_TAG_LEN 4

typedef struct {
	u_char  destinationHostMacAddress[ETHER_ADDR_LEN];       // destination host address
	u_char  sourceHostMacAddress[ETHER_ADDR_LEN];            // source host address
	u_short protocolType;                     			     // type of the encapsulated protocol
} EthernetHeader;

typedef struct {
	u_short packetType;
	u_short byteOrder;
	u_short addrLen;
	u_char  foreignMacAddress[ETHER_ADDR_LEN];       		// remote host address
	u_short unused;
	u_short protocolType;                     			    // type of the encapsulated protocol
} EthernetSLLHeader;

typedef struct {
	u_int32_t  	vlanTag;
	u_short 	protocolType;                     			     // type of the encapsulated protocol
} VlanHeader;

typedef struct {
	u_char  ipVersionAndLenght;                              // version >> 4
	u_char  ipTos;                                           // type of service
	u_short ipLenght;                                        // total length
	u_short ipId;                                            // identification
	u_short ipOffset;                                        // fragment offset field
	u_char  ipTtl;                                           // time to live
	u_char  ipProtocol;                                      // protocol
	u_short ipChecksum;                                      // checksum
	struct  in_addr ipSourceAddress;    // source and destination address
	struct  in_addr ipDestinationAddress;
} IpHeader;

typedef struct {
    u_short   tcpSourcePort;			// source port
    u_short   tcpDestinationPort;   	// destination port
    u_int32_t tcpSequenceNumber;    	// sequence number
    u_int32_t tcpAckNumber;         	// acknowledgement number
    u_char    tcpDataOffsetAndReseve;   // data offset + reserved bits
    u_char    tcpFlags;					// tcp flags
    u_short   tcpWindowSize;			// tcp congestion window size */
    u_short   tcpChecksum;              // checksum
    u_short   tcpUrgencyPointer;		// urgent pointer
} TcpHeader;

typedef struct {
    u_short   udpSourcePort;			// source port
    u_short   udpDestinationPort;   	// destination port
    u_short   length;					// UDP header + UDP data
    u_short   udpChecksum;              // checksum
} UdpHeader;

#endif /* NETWORKHEADERS_H_ */

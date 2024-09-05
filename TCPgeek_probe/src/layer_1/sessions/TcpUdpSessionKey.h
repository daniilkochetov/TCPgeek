/*
 *	TcpUdpSessionKey.h
 *
 *	Created on: Mar 28, 2022
 *	Last modified on: Mar 28, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TcpSessionKey - Describes unique identifier of the session
 *				  defines '==' operator and hashing function for further usage in
 *				  std::unordered_map<TcpSessionKey, TcpSession, HashFn>
 *				Layer 1 - raw data nutrition and its transformation to the
 *				  universal data objects that can be used for further analysis.
 */

#ifndef TCPUDPSESSIONKEY_H_
#define TCPUDPSESSIONKEY_H_

#include <arpa/inet.h> // for inet_ntop
#include <unordered_map>

#include "layer_1/sessions/IpSessionKey.h"

#define MAX_TCP_SESSION_STR_LEN 64

class TcpUdpSessionKey {
public:
	IpSessionKey m_ipSessionKey;
	in_addr 	m_clientIpRaw, m_serverIpRaw; //32 bits or u_int32_t
	u_short 	m_clientPort, m_serverPort; //16 bits

	TcpUdpSessionKey() : m_ipSessionKey(),
						 m_clientPort {0},
						 m_serverPort {0} {
				m_clientIpRaw.s_addr = 0;
				m_serverIpRaw.s_addr = 0;
			}
	TcpUdpSessionKey(const u_short t_cPort, const u_short t_sPort, const in_addr t_cIpRaw, const in_addr t_sIpRaw, const IpSessionKey t_ipSessionKey) {
			m_ipSessionKey = t_ipSessionKey;
			m_clientIpRaw = t_cIpRaw;
			m_serverIpRaw = t_sIpRaw;
			m_clientPort = t_cPort;
			m_serverPort = t_sPort;
	}
	void updateTcpUdpSessionKey(const u_short t_cPort, const u_short t_sPort, const in_addr t_cIpRaw,
								const in_addr t_sIpRaw, const IpSessionKey t_ipSessionKey) {
		m_ipSessionKey = t_ipSessionKey;
		m_clientIpRaw = t_cIpRaw;
		m_serverIpRaw = t_sIpRaw;
		m_clientPort = t_cPort;
		m_serverPort = t_sPort;
	}
	bool operator == (const TcpUdpSessionKey &other) const {
		return (m_serverPort == other.m_serverPort &&
	             m_clientPort == other.m_clientPort &&
				 m_clientIpRaw.s_addr == other.m_clientIpRaw.s_addr &&
				 m_serverIpRaw.s_addr == other.m_serverIpRaw.s_addr &&
				 m_ipSessionKey == other.m_ipSessionKey);
	}
	TcpUdpSessionKey& operator = (const TcpUdpSessionKey other)
	{
		m_clientIpRaw = other.m_clientIpRaw;
		m_serverIpRaw = other.m_serverIpRaw;
		m_clientPort = other.m_clientPort;
		m_serverPort = other.m_serverPort;
		m_ipSessionKey = other.m_ipSessionKey;
		return *this;
	}
};

class TcpUdpSessionHashFn : public IpSessionHashFn {
public:
	std::hash<u_short> hash_u_short;
	std::hash<u_int32_t> hash_u_int32_t;

	std::size_t operator()(const TcpUdpSessionKey& k) const
	{
		std::size_t res = 0;
		res ^= IpSessionHashFn::operator ()(k.m_ipSessionKey);
		res ^= hash_u_int32_t(k.m_clientIpRaw.s_addr);// + 0x9e3779b9 + (res << 6) + (res >> 2);
		res ^= hash_u_int32_t(k.m_serverIpRaw.s_addr);// + 0x9e3779b9 + (res << 6) + (res >> 2);
		res ^= hash_u_short(k.m_serverPort);// + 0x9e3779b9 + (res << 6) + (res >> 2);
		res ^= hash_u_short(k.m_clientPort);// + 0x9e3779b9 + (res << 6) + (res >> 2);
		return res;
	}
};




#endif /* TCPUDPSESSIONKEY_H_ */

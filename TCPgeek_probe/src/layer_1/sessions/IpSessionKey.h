/*
 *	IpSessionKey.h
 *
 *	Created on: Aug 10, 2023
 *	Last modified on: Aug 10, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef IPSESSIONKEY_H_
#define IPSESSIONKEY_H_

#include <arpa/inet.h> // for inet_ntop

class IpSessionKey {
protected:

public:
	u_char m_ipProtocol;

	IpSessionKey() {
		m_ipProtocol = 0;
	};
	IpSessionKey(const u_char t_ipProtocol) {
		m_ipProtocol = t_ipProtocol;
	}
	void updateIpSessionKey(const u_char t_ipProtocol) {
		m_ipProtocol = t_ipProtocol;
	}
	bool operator == (const IpSessionKey &other) const {
		return (m_ipProtocol == other.m_ipProtocol);
	}
	IpSessionKey& operator = (const IpSessionKey other)
	{
		m_ipProtocol = other.m_ipProtocol;
		return *this;
	}
};

class IpSessionHashFn {
public:
	std::hash<u_char> hash_char;
	std::size_t operator()(const IpSessionKey& k) const
	{
		std::size_t res = hash_char(k.m_ipProtocol);// + 0x9e3779b9 + (res << 6) + (res >> 2);
		return res;
	}
};

#endif /* IPSESSIONKEY_H_ */

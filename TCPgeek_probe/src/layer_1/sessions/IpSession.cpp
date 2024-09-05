/*
 *	IpSession.cpp
 *
 *	Created on: Aug 10, 2023
 *	Last modified on: Aug 10, 2023
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/sessions/IpSession.h"

IpSession::IpSession(const unsigned char t_ipProtocol):	m_totalBytes {0}, m_ipProtocol {t_ipProtocol} {
}

void IpSession::update(const Packet* t_packet) {
	m_totalBytes += t_packet->getTotalLen();
}

IpSession::IpSession() : m_totalBytes {0}, m_ipProtocol {0} {
}

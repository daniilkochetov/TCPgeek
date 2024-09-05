/*
 *	ProgramProperties.cpp
 *
 *	Created on: Oct 11, 2023
 *	Last modified on: March 22, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "ProgramProperties.h"

std::string ProgramProperties::m_logConfigFileName;
unsigned long ProgramProperties::m_granularity;
unsigned long ProgramProperties::m_idleTcpSessionTimeout;
unsigned long ProgramProperties::m_maxTcpSessions;
unsigned long ProgramProperties::m_deduplicationBufferSize;
unsigned long ProgramProperties::m_deduplicationTimeout;
bool ProgramProperties::m_promiscuous;
bool ProgramProperties::m_restartOnDrops;
unsigned long ProgramProperties::m_pcapBufferTimeout;
unsigned long ProgramProperties::m_pcapBufferSize;
std::string ProgramProperties::m_source;
std::string ProgramProperties::m_bpfExpression;
std::string ProgramProperties::m_servicePortsStr;
std::string ProgramProperties::m_localSubnetsStr;
std::string ProgramProperties::m_statisticsFileNameTemplate;
std::string ProgramProperties::m_statisticsOwnership;
unsigned long ProgramProperties::m_statisticsRetentionPeriodH;
unsigned long ProgramProperties::m_maxMemoryUsageKB;

ProgramProperties::ProgramProperties(const std::string configFileName) { //throws exceptions
			ConfigFile cf(configFileName);
			ProgramProperties::m_logConfigFileName = cf.value("general","loggingConfigurationFile");

			log4cpp::PropertyConfigurator::configure(ProgramProperties::m_logConfigFileName);
			ProgramProperties::m_granularity = std::stoul(cf.value("general", "granularity"),nullptr,10);
			ProgramProperties::m_statisticsFileNameTemplate = cf.value("general","statisticsFileNameTemplate");
			ProgramProperties::m_statisticsRetentionPeriodH = std::stoul(cf.value("general", "statisticsRetentionPeriodH"),nullptr,10);
			ProgramProperties::m_statisticsOwnership = cf.value("general", "statisticsOwnership");
			ProgramProperties::m_restartOnDrops = std::stoul(cf.value("general", "restartOnDrops"),nullptr,10);
			ProgramProperties::m_maxMemoryUsageKB = std::stoul(cf.value("general", "maxMemoryUsageKB"),nullptr,10);

			ProgramProperties::m_idleTcpSessionTimeout = std::stoul(cf.value("networking", "idleTcpSessionTimeout"),nullptr,10);
			ProgramProperties::m_maxTcpSessions = std::stoul(cf.value("networking", "maxTcpSessions"),nullptr,10);
			ProgramProperties::m_deduplicationBufferSize = std::stoul(cf.value("networking", "deduplicationBufferSize"),nullptr,10);
			ProgramProperties::m_deduplicationTimeout = std::stoul(cf.value("networking", "deduplicationTimeout"),nullptr,10);
			ProgramProperties::m_promiscuous = std::stoul(cf.value("networking", "promiscuous"),nullptr,10);
			ProgramProperties::m_pcapBufferTimeout = std::stoul(cf.value("networking", "pcap_packet_buffer_timeout"),nullptr,10);
			ProgramProperties::m_pcapBufferSize = std::stoul(cf.value("networking", "pcap_buffer_size"),nullptr,10);
			ProgramProperties::m_source = cf.value("networking","source");
			ProgramProperties::m_bpfExpression = cf.value("networking","bpfExpression");
			ProgramProperties::m_servicePortsStr  = cf.value("networking","servicePorts");
			ProgramProperties::m_localSubnetsStr = cf.value("networking","localSubnets");
}

unsigned long ProgramProperties::getDeduplicationTimeout() {
	return ProgramProperties::m_deduplicationTimeout;
}

const std::string& ProgramProperties::getBpfExpression() {
	return ProgramProperties::m_bpfExpression;
}

unsigned long ProgramProperties::getDeduplicationBufferSize() {
	return ProgramProperties::m_deduplicationBufferSize;
}

unsigned long ProgramProperties::getGranularity(){
	return ProgramProperties::m_granularity;
}

unsigned long ProgramProperties::getIdleTcpSessionTimeout() {
	return ProgramProperties::m_idleTcpSessionTimeout;
}

const std::string& ProgramProperties::getLocalSubnetsStr() {
	return ProgramProperties::m_localSubnetsStr;
}

const std::string& ProgramProperties::getLogConfigFileName() {
	return ProgramProperties::m_logConfigFileName;
}

unsigned long ProgramProperties::getMaxTcpSessions() {
	return ProgramProperties::m_maxTcpSessions;
}

unsigned long ProgramProperties::getPcapBufferSize() {
	return ProgramProperties::m_pcapBufferSize;
}

unsigned long ProgramProperties::getPcapBufferTimeout() {
	return ProgramProperties::m_pcapBufferTimeout;
}

bool ProgramProperties::isPromiscuous() {
	return ProgramProperties::m_promiscuous;
}

bool ProgramProperties::doRestartOnDrops() {
	return ProgramProperties::m_restartOnDrops;
}

const std::string& ProgramProperties::getServicePortsStr() {
	return ProgramProperties::m_servicePortsStr;
}

const std::string& ProgramProperties::getStatisticsLogFile() {
	return m_statisticsFileNameTemplate;
}

const u_int32_t ProgramProperties::getMaxMemoryUsageKb() {
	return m_maxMemoryUsageKB;
}

const std::string& ProgramProperties::getStatisticsOwnership() {
	return m_statisticsOwnership;
}

unsigned long ProgramProperties::getStatisticsRetentionPeriodH() {
	return m_statisticsRetentionPeriodH;
}

const std::string& ProgramProperties::getSource() {
	return ProgramProperties::m_source;
}



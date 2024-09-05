/*
 *	ProgramProperties.h
 *
 *	Created on: Oct 11, 2023
 *	Last modified on: March 22, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef PROGRAMPROPERTIES_H_
#define PROGRAMPROPERTIES_H_

#include <log4cpp/Category.hh> // for log4cpp::Category
#include <log4cpp/PropertyConfigurator.hh> //for log4cpp::PropertyConfigurator

#include "thirdpartyCode/ConfigFile.h" //for properties

class ProgramProperties {
private:
	static unsigned long m_granularity;
	static unsigned long m_idleTcpSessionTimeout;
	static unsigned long m_maxTcpSessions;
	static unsigned long m_deduplicationBufferSize;
	static unsigned long m_deduplicationTimeout;
	static bool m_promiscuous;
	static unsigned long m_pcapBufferTimeout;
	static unsigned long m_pcapBufferSize;
	static std::string m_source;
	static std::string m_bpfExpression;
	static std::string m_servicePortsStr;
	static std::string m_localSubnetsStr;
	static std::string m_logConfigFileName;
	static std::string m_statisticsFileNameTemplate;
	static std::string m_statisticsOwnership;
	static unsigned long m_statisticsRetentionPeriodH;
	static bool m_restartOnDrops;
	static unsigned long m_maxMemoryUsageKB;
public:
	ProgramProperties(const std::string configFileName);
	static unsigned long getDeduplicationTimeout();
	static const std::string& getBpfExpression();
	static unsigned long getDeduplicationBufferSize();
	static unsigned long getGranularity();
	static unsigned long getIdleTcpSessionTimeout();
	static const std::string& getLocalSubnetsStr();
	static const std::string& getLogConfigFileName();
	static unsigned long getMaxTcpSessions();
	static unsigned long getPcapBufferSize();
	static unsigned long getPcapBufferTimeout();
	static bool isPromiscuous();
	static bool doRestartOnDrops();
	static const std::string& getServicePortsStr();
	static const std::string& getSource();
	static const std::string& getStatisticsLogFile();
	static unsigned long getStatisticsRetentionPeriodH();
	static const std::string& getStatisticsOwnership();
	static const u_int32_t getMaxMemoryUsageKb();
};

#endif /* PROGRAMPROPERTIES_H_ */

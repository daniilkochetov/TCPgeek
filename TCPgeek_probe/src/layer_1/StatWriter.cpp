/*
 *	StatWriter.cpp
 *
 *	Created on: Oct 12, 2023
 *	Last modified on: March 22, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#include "layer_1/StatWriter.h"

StatWriter::StatWriter() { //throws exceptions
	log4cpp::Category& logRoot = log4cpp::Category::getRoot();
	std::size_t fileNamePos = ProgramProperties::getStatisticsLogFile().find_last_of("/\\");
	if (fileNamePos != std::string::npos) {
		m_directory = ProgramProperties::getStatisticsLogFile().substr(0, fileNamePos);
		if (!validateDirectory(m_directory.c_str())) {
			throw std::runtime_error("Can't use the directory specified in statisticsFileNameTemplate parameter of the configuration");
		}
	} else {
		m_directory = "";
	}
	m_fileNameTemplate = ProgramProperties::getStatisticsLogFile().substr(fileNamePos + 1);
	std::size_t fileExtPos = m_fileNameTemplate.find_last_of(".");
	if (fileExtPos != std::string::npos) {
		m_fileExt  = m_fileNameTemplate.substr(fileExtPos + 1);
	} else {
		m_fileExt = "";
	}
	m_fileNameTemplate = m_fileNameTemplate.substr(0, fileExtPos);
	if (m_fileNameTemplate == "") {
		throw std::runtime_error("No statisticsFileNameTemplate is specified in the configuration");
	}

	//std::string token;
	std::stringstream ss(ProgramProperties::getStatisticsOwnership());
	std::getline(ss, m_oUser, ':');
	std::getline(ss, m_oGroup, ':');
	logRoot.info("Statistics Files will be owned by " + m_oUser + ':' + m_oGroup);
	removeOldStat();
}

bool StatWriter::validateDirectory(const char* pzPath) {
	if ( pzPath == NULL) return false;
	DIR *pDir;
	bool success = false;

	pDir = opendir (pzPath);
	if (pDir != NULL) {
		success = true;
		(void) closedir (pDir);
	} else {
		std::string command = pzPath;
		command = "mkdir -m 644 -p " + command;
		const int err = std::system(command.c_str());
		if (err == -1) {
			success = false;
		} else {
			success = true;
		}
	}
	return success;
}

bool StatWriter::removeOldStat() {
	bool success = false;
	std::string command;
	unsigned int retentionInMinutes = ProgramProperties::getStatisticsRetentionPeriodH()*60;
	if (retentionInMinutes == 0) {
		//keep forever
		return true;
	}
	command = "find \"" + m_directory + "\" -iregex \".*"
					+ m_fileNameTemplate + ".*\\."
					+ m_fileExt + "\" -mmin +" + std::to_string(retentionInMinutes)
					+ " -exec rm -f '{}' \\;";

	const int err = std::system(command.c_str());
	if (err == -1) {
		success = false;
	} else {
		success = true;
	}
	return success;
}

void StatWriter::writeStat(SafeQueue<StatRecord>* m_sessionsStatQueue) {
	StatRecord statRecord;
	char clientIpStr[INET_ADDRSTRLEN];
	char serverIpStr[INET_ADDRSTRLEN];
	char timestamp_str[TIMESTAMP_STR_MAX_SIZE];
	char sessionKeyStr[SESSION_KEY_STR_MAX_SIZE];
	long int timestampEpoch;
	struct tm *timestamp_tm;
	char sessionTopology;
	char statString[512];
	std::ofstream statFileHandler;
	std::string tmpFileName = m_directory + "/" + m_fileNameTemplate + ".tmp";

	statFileHandler.open(tmpFileName.c_str(), std::ios_base::app);
	while (m_sessionsStatQueue->dequeue(statRecord)) {
		inet_ntop(AF_INET, &(statRecord.getTcpUdpSessionKey().m_clientIpRaw), clientIpStr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(statRecord.getTcpUdpSessionKey().m_serverIpRaw), serverIpStr, INET_ADDRSTRLEN);
		timestampEpoch = (long int) statRecord.getTimestampEpoch()/1000000;
		timestamp_tm = gmtime(&timestampEpoch);
		strftime(timestamp_str, sizeof timestamp_str, "%Y-%m-%d %H:%M:%S", timestamp_tm);

		sessionTopology = LocalSubnets::getConnectionTopology(statRecord.getTcpUdpSessionKey().m_serverIpRaw, statRecord.getTcpUdpSessionKey().m_clientIpRaw);

		sprintf(sessionKeyStr, "%s	%" PRIu16 "	%s	%" PRIu16, clientIpStr, statRecord.getTcpUdpSessionKey().m_clientPort,
				serverIpStr, statRecord.getTcpUdpSessionKey().m_serverPort);

		sprintf(statString, "%s	%" PRIu8  // Timestamp, IP Protocol
				"	%s	%c"	  				  // Client IP, client	port, Server IP, server	port, connectionTopology
				"	%" PRIu64 "	%" PRIu64 // Packets
				"	%" PRIu64 "	%" PRIu64 // Bytes
				"	%" PRIu64 "	%" PRIu64 // Efficient Bytes
				"	%" PRIu64 "	%" PRIu64 // Duplicates
				"	%" PRIu64 "	%" PRIu64 // Out-Of-Order
				"	%" PRIu64 "	%" PRIu64 // ActiveGaps
				"	%" PRIu64 "	%" PRIu64 // Retransmits
				"	%" PRIu64 // Operations
				"	%" PRIu64 "	%" PRIu64 "	%" PRIu64 "	%" PRIu64 //Client Idle Time, Request Time, Server Think Time, Response Time in milliseconds
				"	%" PRIu64 "	%" PRIu32 // Total Session Idle Time in milliseconds, Error Code
				"	%" PRIu64, // RTT
				timestamp_str, statRecord.getIpProtocol(),
				sessionKeyStr, sessionTopology,
				statRecord.getClientPackets(), statRecord.getServerPackets(), statRecord.getClientBytes(), statRecord.getServerBytes(),
				statRecord.getClientEfficientBytes(), statRecord.getServerEfficientBytes(),
				statRecord.getClientDuplicatesCounter(), statRecord.getServerDuplicatesCounter(),
				statRecord.getClientOutOfOrderCounter(), statRecord.getServerOutOfOrderCounter(),
				statRecord.getClientActiveSequenceGaps(), statRecord.getServerActiveSequenceGaps(),
				statRecord.getClientRetransmits(), statRecord.getServerRetransmits(),
				statRecord.getOperations(),
				statRecord.getClientIdleTime()/1000, statRecord.getRequestTime()/1000, statRecord.getServerThinkTime()/1000, statRecord.getResponseTime()/1000,
				statRecord.getTotalSessionIdleTime()/1000, statRecord.getSessionErrorCode(),
				statRecord.getRtt());
		statFileHandler << statString << std::endl;
		//!DEBUG
		if ((statRecord.getServerActiveSequenceGaps() > 1000) || (statRecord.getClientActiveSequenceGaps() > 1000)) {
			log4cpp::Category& logRoot = log4cpp::Category::getRoot();
			logRoot.warn("Inadequate active sequence gaps identified for %s", statString);
		}
		//------
	}
	statFileHandler.close();
	char *timeStr = getCurrentTime();
	std::string statFileName = m_directory + "/" + m_fileNameTemplate + "_" + timeStr +".log";
	int i = 0;
	while (access(statFileName.c_str(), F_OK) == 0) {
		statFileName = m_directory + "/" + m_fileNameTemplate + std::to_string(i) + "_"+ timeStr +".log";
		i++;
	}
	if (rename(tmpFileName.c_str(), statFileName.c_str()) != 0) {
		log4cpp::Category& logRoot = log4cpp::Category::getRoot();
		logRoot.fatal("Error renaming temp file to statistics file " + statFileName);
	}
	setStatFileOwner(statFileName);
	free(timeStr);
	removeOldStat();
	return;
}

size_t StatWriter::hash_c_string(const char* p, const size_t s,	const size_t prime) {
    size_t result = prime;
    for (size_t i = 0; i < s; ++i) {
        result = p[i] + (result * 31);
    }
    return result;
}

char* StatWriter::getCurrentTime() {
	char *timeStr = (char*) malloc(80 * sizeof(char));
	time_t rawtime;
	struct tm * timeinfo;
	time (&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timeStr,80,"%Y%m%d-%H-%M-%S",timeinfo);
	return timeStr;

}

void StatWriter::setStatFileOwner(std::string fileName) {
	uid_t          uid;
	gid_t          gid;
	struct passwd *pwd;
	struct group  *grp;

	pwd = getpwnam(m_oUser.c_str());
	if (pwd == NULL) {
		log4cpp::Category& logRoot = log4cpp::Category::getRoot();
		logRoot.crit("Failed to get uid for " + std::string(m_oUser));
		return;
	}
	uid = pwd->pw_uid;
    grp = getgrnam(m_oGroup.c_str());
    if (grp == NULL) {
    	log4cpp::Category& logRoot = log4cpp::Category::getRoot();
    	logRoot.crit("Failed to get gid for " + std::string(m_oGroup));
    	return;
    }
    gid = grp->gr_gid;
    if (chown(fileName.c_str(), uid, gid) == -1) {
    	log4cpp::Category& logRoot = log4cpp::Category::getRoot();
    	logRoot.crit("Failed to chown for " + std::string(fileName));
    }

}

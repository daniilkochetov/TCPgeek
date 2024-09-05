/*
 *	StatWriter.h
 *
 *	Created on: Oct 12, 2023
 *	Last modified on: March 22, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */


#ifndef STATWRITER_H_
#define STATWRITER_H_

#define TIMESTAMP_STR_MAX_SIZE 64
#define SESSION_KEY_STR_MAX_SIZE 44

#include <dirent.h>
#include <cstdlib>
#include <log4cpp/Category.hh> // for logging capabilities
#include <fstream>
#include <inttypes.h>
#include <string.h>
#include <sstream>
#include <cstdio>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "ProgramProperties.h"
#include "SafeQueue.h"
#include "layer_1/StatRecord.h"
#include "layer_1/LocalSubnets.h"

class StatWriter {
private:
	std::string m_directory, m_fileNameTemplate, m_fileExt;
	std::string m_oUser;
	std::string m_oGroup;

	bool validateDirectory(const char* pzPath);
	bool removeOldStat();
	size_t hash_c_string(const char* p, const size_t s, const size_t prime);
	char* getCurrentTime();
	void setStatFileOwner(std::string fileName);

public:
	StatWriter();
	void writeStat(SafeQueue<StatRecord>* m_sessionsStatQueue);
};

#endif /* STATWRITER_H_ */

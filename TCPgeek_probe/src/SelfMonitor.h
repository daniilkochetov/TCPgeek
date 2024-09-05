#ifndef SELFMONITOR_H_
#define SELFMONITOR_H_

#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "sys/times.h"
#include "sys/vtimes.h"


class SelfMonitor {
private:

	clock_t m_lastCPU;
	clock_t m_lastSysCPU;
	clock_t m_lastUserCPU;
	int m_numProcessors;
	int parseLine(char* t_line);

public:
	SelfMonitor();
	u_int32_t getVirtualMemoryKb();
	u_int32_t getPhysicalMemoryKb();
	double getCpuUsagePecentage();
	static u_int64_t getCpuTicksStart(); //too slow
	static u_int64_t getCpuTicksEnd(); //too slow
	static u_int64_t getCpuTicks(); //fast, but not serialized
	static timespec tsDiff(timespec t_end, timespec t_start);
};

#endif /* SELFMONITOR_H_ */

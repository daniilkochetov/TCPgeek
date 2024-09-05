#include <SelfMonitor.h>

SelfMonitor::SelfMonitor() {
    FILE* file;
    struct tms timeSample;
    char line[128];

    m_lastCPU = times(&timeSample);
    m_lastSysCPU = timeSample.tms_stime;
    m_lastUserCPU = timeSample.tms_utime;

    file = fopen("/proc/cpuinfo", "r");
    m_numProcessors = 0;
    while(fgets(line, 128, file) != NULL){
        if (strncmp(line, "processor", 9) == 0) m_numProcessors++;
    }
    fclose(file);
}

int SelfMonitor::parseLine(char* t_line) {
    // This assumes that a digit will be found and the line ends in " Kb".
    int i = strlen(t_line);
    const char* p = t_line;
    while (*p <'0' || *p > '9') p++;
    t_line[i-3] = '\0';
    i = atoi(p);
    return i;
}

u_int32_t SelfMonitor::getVirtualMemoryKb() {
    FILE* file = fopen("/proc/self/status", "r");
    int result = -1;
    char line[128];

    while (fgets(line, 128, file) != NULL){
        if (strncmp(line, "VmSize:", 7) == 0){
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    return result;
}

u_int32_t SelfMonitor::getPhysicalMemoryKb() {
    FILE* file = fopen("/proc/self/status", "r");
    int result = -1;
    char line[128];

    while (fgets(line, 128, file) != NULL){
        if (strncmp(line, "VmRSS:", 6) == 0){
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    return result;
}

double SelfMonitor::getCpuUsagePecentage() {
    struct tms timeSample;
    clock_t now;
    double percent;

    now = times(&timeSample);
    if (now <= m_lastCPU || timeSample.tms_stime < m_lastSysCPU ||
        timeSample.tms_utime < m_lastUserCPU){
        percent = -1.0;
    }
    else{
        percent = (timeSample.tms_stime - m_lastSysCPU) +
            (timeSample.tms_utime - m_lastUserCPU);
        percent /= (now - m_lastCPU);
        //percent /= m_numProcessors;
        percent *= 100;
    }
    m_lastCPU = now;
    m_lastSysCPU = timeSample.tms_stime;
    m_lastUserCPU = timeSample.tms_utime;

    return percent;
}

u_int64_t SelfMonitor::getCpuTicksStart() {
	u_int32_t lo;
	u_int32_t hi;

	asm volatile ("CPUID\n\t"
				  "RDTSC\n\t"
				  "mov %%edx, %0\n\t"
				  "mov %%eax, %1\n\t": "=r" (hi), "=r" (lo)::
				  "%rax", "%rbx", "%rcx", "%rdx");

	//CPUID guarantees from reordering, but makes execution too heavy
	return ((u_int64_t)hi << 32) | lo;

}

u_int64_t SelfMonitor::getCpuTicksEnd() {
	u_int32_t lo;
	u_int32_t hi;
	asm volatile("RDTSCP\n\t"
				 "mov %%edx, %0\n\t"
				 "mov %%eax, %1\n\t"
				 "CPUID\n\t": "=r" (hi), "=r" (lo)::
				 "%rax", "%rbx", "%rcx", "%rdx");
	 __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));

	//CPUID guarantees from reordering, but makes execution too heavy
	return ((u_int64_t)hi << 32) | lo;
}

u_int64_t SelfMonitor::getCpuTicks() {
	u_int32_t lo;
	u_int32_t hi;

	 __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));

	return ((u_int64_t)hi << 32) | lo;
}

timespec SelfMonitor::tsDiff(timespec t_end, timespec t_start)
{
    timespec temp;

    if ((t_end.tv_nsec-t_start.tv_nsec)<0)
    {
            temp.tv_sec = t_end.tv_sec-t_start.tv_sec-1;
            temp.tv_nsec = 1000000000L+t_end.tv_nsec-t_start.tv_nsec;
    }
    else
    {
            temp.tv_sec = t_end.tv_sec-t_start.tv_sec;
            temp.tv_nsec = t_end.tv_nsec-t_start.tv_nsec;
    }
    return temp;
}

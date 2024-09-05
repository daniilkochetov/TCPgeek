/*
 *	TCPgeek_rt.cpp
 *
 *	Created on: Nov 30, 2021
 *	Last modified on: Nov 30, 2021
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : TCPgeek_rt - core functionality
 *	Layer 0 - fundamental routines, initiation and termination,
 *			  continuous threads control, proper application shutdown,
 *			  basic auxiliary classes and functions
 *
 */


#include <csignal> // for signal management functions;
#include <future> // for std::condition_variable, std::atomic, and mutex related functions and types
#include <cstring> // for strcmp(...)
#include <unordered_set>
#include <algorithm>  //for std::replace
#include <unistd.h>
#include <inttypes.h>



#include <log4cpp/Category.hh> // for log4cpp::Category
#include <log4cpp/PropertyConfigurator.hh> //for log4cpp::PropertyConfigurator

//#include "thirdpartyCode/ConfigFile.h" //for properties
#include "ProgramProperties.h"
#include "layer_1/KnownPorts.h"
#include "layer_1/Sniffer.h" // connection to Layer 1 functionality
#include "stdlib.h"

int homebrewShutdownSignalHandler(sigset_t& t_sigSet,
									std::condition_variable& t_shutdownCondVar,
									std::atomic<bool>& t_shutdownRequested,
									std::mutex& t_shutdownCondVarMutex) {
	/*PRGORAM TERMINATION HANDLER THREAD FUCNTION*/
	/*as per https://thomastrapp.com/blog/signal-handler-for-multithreaded-c++/*/

	int signum = 0;
	// wait until a signal is delivered:
	sigwait(&t_sigSet, &signum);

	//command all the threads to shutdown
	{
		std::unique_lock<std::mutex> lock(t_shutdownCondVarMutex);
		t_shutdownRequested.store(true, std::memory_order_relaxed);
	}
	t_shutdownCondVar.notify_all(); // notify all waiting threads to check their predicate:

	return signum;
}

int snifferControl(std::atomic<bool>& t_shutdownRequested,
				   std::mutex& t_shutdownCondVarMutex,
				   std::condition_variable& t_shutdownCondVar,
				   Sniffer *t_sniffer) {

	log4cpp::Category& logRoot = log4cpp::Category::getRoot();

	//Periodically aggregates TCP sessions and safely breaks pcap_loop() when shutdown_requested == true

	while(t_shutdownRequested.load(std::memory_order_relaxed) == false)
	{
		std::unique_lock<std::mutex> lock(t_shutdownCondVarMutex);
		// when the condition variable is woken up and this predicate returns true, the wait is stopped:
		t_shutdownCondVar.wait_for(lock, std::chrono::seconds(ProgramProperties::getGranularity()),
								 [&t_shutdownRequested]() { return t_shutdownRequested.load(std::memory_order_relaxed); });

		//STATISTICS AGGREGATION
		t_sniffer->aggregateSessions();
		//to be continued...
	}
	t_sniffer->stopCapture();
	logRoot.info("Control thread stopped");

	return 0;
}

int main(int argc, char* argv[]) {

	//****READ CONFIGURATION****
	std::string configFileName = "./TCPgeek_rt.conf";
	//check if configuration file is specified in the command line
	if ((argc == 3) && (strcmp(argv[1],"-c") == 0)) {
		configFileName = argv[2];
	}

	//taking options from the configuration file
	printf("Starting TCPgeek_rt with the configuration file: %s\n", configFileName.c_str());
	try {
		ProgramProperties* programProperties = new ProgramProperties(configFileName);
		printf("Logging as per %s\n", ProgramProperties::getLogConfigFileName().c_str());
		//initializing logger
		log4cpp::Category& logRoot = log4cpp::Category::getRoot();
		logRoot.info("BPF filter expression is '%s'", ProgramProperties::getBpfExpression().c_str());
		logRoot.info("Granularity is %" PRIu32 " seconds", ProgramProperties::getGranularity());
		logRoot.info("Maximum number of simultaneously processed TCP sessions is %" PRIu32, ProgramProperties::getMaxTcpSessions());
		logRoot.info("Idle timeout for TCP session is %" PRIu32 " seconds", ProgramProperties::getIdleTcpSessionTimeout());
		logRoot.info("Deduplication buffer size is %" PRIu32 " packets", ProgramProperties::getDeduplicationBufferSize());
		logRoot.info("Deduplication timeout is %" PRIu32 " milliseconds", ProgramProperties::getDeduplicationTimeout());
		logRoot.info("Pcap packet buffer timeout is %" PRIu32 " milliseconds", ProgramProperties::getPcapBufferTimeout());
		logRoot.info("Pcap buffer size is %" PRIu32 " bytes", ProgramProperties::getPcapBufferSize());
		logRoot.info("Source: %s", ProgramProperties::getSource().c_str());

		//****INITIALIZING LAYER 1****
		Sniffer *sniffer = new Sniffer();

		//****PRGORAM TERMINATION HANDLING****
		//as per https://thomastrapp.com/blog/signal-handler-for-multithreaded-c++/

		std::condition_variable shutdownCondVar;
		std::atomic<bool> shutdownRequested;
		std::mutex shutdownCondVarMutex;

		sigset_t sigSet;
		sigemptyset(&sigSet);
		sigaddset(&sigSet, SIGINT);
		sigaddset(&sigSet, SIGTERM);
		pthread_sigmask(SIG_BLOCK, &sigSet, nullptr);

		shutdownRequested.store(false, std::memory_order_relaxed);

		std::future<int> ft_signal_handler = std::async(std::launch::async,
														homebrewShutdownSignalHandler,
														std::ref(sigSet),
														std::ref(shutdownCondVar),
														std::ref(shutdownRequested),
														std::ref(shutdownCondVarMutex));

		//****STARTING CONTROL THREAD FOR SNIFFER****
		//it periodically aggregates TCP sessions and safely breaks pcap_loop() when shutdown_requested == true

		std::future<int> res = std::async(std::launch::async, snifferControl,
											std::ref(shutdownRequested),
											std::ref(shutdownCondVarMutex),
											std::ref(shutdownCondVar),
											sniffer);

		//****STARTING CAPTURE****
		logRoot.info("Starting capture");
		sniffer->startCapture();
		//command all the threads to shutdown
		kill(getpid(),SIGINT);
		res.wait();
		ft_signal_handler.wait();
		//int pcap_res = sniffer->startCapture();
		int pcap_res = sniffer->getSnifferEndReason();
		delete programProperties;
		delete sniffer;
		//Capture has been terminated with snifferControl()
		logRoot.info("Capture stopped with %d exit code", pcap_res);
		logRoot.info("Alright then");
		logRoot.info("***********************************************************\n");
		return pcap_res;
	} catch (std::exception& e) {
		printf("Exception when reading configuration file:\n     %s\nExitting.", e.what());
		return EXIT_FAILURE;
	}

}

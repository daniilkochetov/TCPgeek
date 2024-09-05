/*
 *	SafeQueue.h
 *
 *	Created on: Apr 11, 2022
 *	Last modified on: Apr 11, 2022
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 *	Description : SafeQueue - Thread safe queue for log messages transferring from
 *	main thread of capturing to controlThread where they stored to
 *	the disk. Used at Layer 1 for logging TCP sessions and packets.
 *
 *	Layer 0 - fundamental routines, initiation and termination,
 *			  continuous threads control, proper application shutdown,
 *			  basic auxiliary classes and functions
 *
 */

#ifndef SAFEQUEUE_H_
#define SAFEQUEUE_H_

#include <queue>
#include <mutex>

// A threadsafe-queue.
template <class T>
class SafeQueue
{
private:
	std::queue<T> q;
	mutable std::mutex m;

public:
	SafeQueue() : q(), m() {

	}
	~SafeQueue() {

	}

	// Add an element to the queue.
	void enqueue(const T t) {
		std::lock_guard<std::mutex> lock(m);
		q.push(t);
	}

	// Get the "front"-element.
	bool dequeue(T &t_val) {
		std::unique_lock<std::mutex> lock(m);
		if (!q.empty()){
			t_val = q.front();
			q.pop();
			return true;
		}
		return false;
	}

	const uint64_t size() const {
		std::unique_lock<std::mutex> lock(m);
		return q.size();
	}

};



#endif /* SAFEQUEUE_H_ */

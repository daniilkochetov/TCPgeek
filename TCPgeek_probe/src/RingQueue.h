/*
 *	RingQueue.h
 *
 *	Created on: Apr 11, 2022
 *	Last modified on: March 22, 2024
 *
 *	Copyright (C) 2024  Daniil Kochetov (unixguide@narod.ru)
 *
 *	See the COPYING file for the terms of usage and distribution.
 *
 */

#ifndef RINGQUEUE_H_
#define RINGQUEUE_H_

#include <queue>

template <class T>
class RingQueue {
private:
	std::queue<T> m_q;
	unsigned int m_maxSize;
public:
	RingQueue(unsigned int t_maxSize) : m_q() {
		m_maxSize = t_maxSize;
	}

	// Add an element to the queue.
	void enqueue(const T t) {
		if (m_q->size() == m_maxSize) {
			m_q->c.pop_front();
		}
		m_q.push(t);
	}

	// Get the "front"-element.
	bool dequeue(T &t_val) {
		if (!m_q.empty()){
			t_val = m_q.front();
			m_q.pop();
			return true;
		}
		return false;
	}
};

#endif /* RINGQUEUE_H_ */

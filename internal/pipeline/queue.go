// Package pipeline is the bounded metadata queue between the proxy and detection.
package pipeline

import (
	"sync"

	"github.com/kirank55/keman/internal/model"
)

type Queue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	items   []model.Event
	max     int
	dropped int64
	closed  bool
}

func New(max int) *Queue {
	if max <= 0 {
		max = 10_000
	}
	q := &Queue{max: max}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Push enqueues an event. When the queue is full the oldest event is dropped.
func (q *Queue) Push(ev model.Event) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		q.dropped++
		return 1
	}
	dropped := 0
	if len(q.items) >= q.max {
		q.items = q.items[1:]
		q.dropped++
		dropped = 1
	}
	q.items = append(q.items, ev)
	q.cond.Signal()
	return dropped
}

// Pop waits for an event. After Close it drains what remains and then returns false.
func (q *Queue) Pop() (model.Event, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return model.Event{}, false
	}
	ev := q.items[0]
	q.items = q.items[1:]
	return ev, true
}

func (q *Queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *Queue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

func (q *Queue) Dropped() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

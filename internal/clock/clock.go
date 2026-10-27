// Package clock is the time source for every decision that depends on time.
package clock

import (
	"sync"
	"time"
)

// Clock returns the current instant and can schedule a wait.
// Production uses the wall clock. Tests use Fake so history can be replayed.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// System is the wall clock in UTC.
type System struct{}

func (System) Now() time.Time { return time.Now().UTC() }

func (System) After(d time.Duration) <-chan time.Time { return time.After(d) }

type waiter struct {
	deadline time.Time
	ch       chan time.Time
}

// Fake is a clock tests move by hand. After fires when Set or Advance
// reaches the deadline. A deadline that is already due fires immediately.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	waiters []waiter
}

func NewFake(t time.Time) *Fake {
	return &Fake{now: t.UTC()}
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	f.now = t.UTC()
	f.fire()
	f.mu.Unlock()
}

func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.fire()
	f.mu.Unlock()
}

func (f *Fake) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	deadline := f.now.Add(d)
	if !deadline.After(f.now) {
		ch <- f.now
		return ch
	}
	f.waiters = append(f.waiters, waiter{deadline: deadline, ch: ch})
	return ch
}

func (f *Fake) fire() {
	keep := f.waiters[:0]
	for _, w := range f.waiters {
		if !w.deadline.After(f.now) {
			select {
			case w.ch <- f.now:
			default:
			}
			continue
		}
		keep = append(keep, w)
	}
	f.waiters = keep
}

// Package scheduler runs a task (a batch active scan) on a recurring interval.
package scheduler

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Scheduler runs task every IntervalMin minutes while enabled.
type Scheduler struct {
	mu          sync.Mutex
	enabled     bool
	intervalMin int
	lastRun     time.Time
	nextRun     time.Time
	running     bool

	path string
	task func(context.Context)
}

type persisted struct {
	Enabled     bool `json:"enabled"`
	IntervalMin int  `json:"intervalMin"`
}

// Status is the scheduler state reported to the UI.
type Status struct {
	Enabled     bool       `json:"enabled"`
	IntervalMin int        `json:"intervalMin"`
	Running     bool       `json:"running"`
	LastRun     *time.Time `json:"lastRun,omitempty"`
	NextRun     *time.Time `json:"nextRun,omitempty"`
}

// New creates a scheduler, loads persisted config, and starts its loop.
func New(path string, task func(context.Context)) *Scheduler {
	s := &Scheduler{path: path, task: task, intervalMin: 60}
	if b, err := os.ReadFile(path); err == nil {
		var p persisted
		if json.Unmarshal(b, &p) == nil {
			s.enabled = p.Enabled
			if p.IntervalMin > 0 {
				s.intervalMin = p.IntervalMin
			}
			if s.enabled {
				s.nextRun = time.Now().Add(time.Duration(s.intervalMin) * time.Minute)
			}
		}
	}
	go s.loop()
	return s
}

func (s *Scheduler) loop() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		due := s.enabled && !s.running && !s.nextRun.IsZero() && time.Now().After(s.nextRun)
		if due {
			s.running = true
		}
		s.mu.Unlock()
		if !due {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		s.task(ctx)
		cancel()
		s.mu.Lock()
		s.lastRun = time.Now()
		s.nextRun = time.Now().Add(time.Duration(s.intervalMin) * time.Minute)
		s.running = false
		s.mu.Unlock()
	}
}

// Set updates and persists the schedule.
func (s *Scheduler) Set(enabled bool, intervalMin int) error {
	s.mu.Lock()
	s.enabled = enabled
	if intervalMin > 0 {
		s.intervalMin = intervalMin
	}
	if enabled {
		s.nextRun = time.Now().Add(time.Duration(s.intervalMin) * time.Minute)
	} else {
		s.nextRun = time.Time{}
	}
	p := persisted{Enabled: s.enabled, IntervalMin: s.intervalMin}
	s.mu.Unlock()
	b, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(s.path, b, 0o600)
}

// Status returns the current state.
func (s *Scheduler) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Enabled: s.enabled, IntervalMin: s.intervalMin, Running: s.running}
	if !s.lastRun.IsZero() {
		lr := s.lastRun
		st.LastRun = &lr
	}
	if !s.nextRun.IsZero() {
		nr := s.nextRun
		st.NextRun = &nr
	}
	return st
}

package hardware

import (
	"sync"
	"time"

	"github.com/mamadouk/kveritas/internal/session"
)

// Sampler periodically captures hardware state in the background.
type Sampler struct {
	interval time.Duration
	mu       sync.Mutex
	samples  []session.HardwareSample
	stop     chan struct{}
	done     chan struct{}
}

// NewSampler creates a new hardware sampler with the given polling interval.
func NewSampler(interval time.Duration) *Sampler {
	return &Sampler{
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start begins background hardware sampling.
func (s *Sampler) Start() {
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		s.capture()
		for {
			select {
			case <-ticker.C:
				s.capture()
			case <-s.stop:
				s.capture()
				return
			}
		}
	}()
}

func (s *Sampler) capture() {
	sample := session.HardwareSample{
		Timestamp: time.Now().UTC(),
		Counters:  DetailedCounters(),
	}
	s.mu.Lock()
	s.samples = append(s.samples, sample)
	s.mu.Unlock()
}

// Stop terminates sampling and returns all collected samples.
func (s *Sampler) Stop() []session.HardwareSample {
	close(s.stop)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.samples
}

package hardware

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// Sampler periodically captures hardware state in the background. Once the run's
// PID is set, it measures only that process tree so other apps on the machine do
// not inflate the readings.
type Sampler struct {
	interval time.Duration
	mu       sync.Mutex
	samples  []session.HardwareSample
	stop     chan struct{}
	done     chan struct{}
	pid      int32
}

// SetPID scopes sampling to the given process and its descendants, and takes a
// baseline sample right away so cumulative counters start near zero.
func (s *Sampler) SetPID(pid int) {
	atomic.StoreInt32(&s.pid, int32(pid))
	s.capture()
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
	// Record only while the run's own process is alive, so samples are all
	// per-process and never mixed with a pre-run or post-exit system reading.
	pid := atomic.LoadInt32(&s.pid)
	if pid == 0 || !ProcessAlive(int(pid)) {
		return
	}
	sample := session.HardwareSample{
		Timestamp: time.Now().UTC(),
		Counters:  ProcessCounters(int(pid)),
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

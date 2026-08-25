package hardware

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// gpuRefreshEvery controls how often the (slower) per-process GPU counters are
// refreshed relative to the cheap /proc counters. At a 100ms tick this refreshes
// the GPU about every 500ms while the CPU-side channels are sampled at ~10 Hz, so
// even short runs accumulate enough samples for the coherence analysis.
const gpuRefreshEvery = 5

// Sampler periodically captures hardware state in the background. Once the run's
// PID is set, it measures only that process tree so other apps on the machine do
// not inflate the readings. The cheap /proc channels are sampled at the tick rate;
// the expensive nvidia-smi channels are refreshed less often and forward-filled.
type Sampler struct {
	interval time.Duration
	mu       sync.Mutex
	samples  []session.HardwareSample
	stop     chan struct{}
	done     chan struct{}
	pid      int32
	lastGPU  session.HardwareCounters
	tick     int
}

// SetPID scopes sampling to the given process and its descendants, and takes a
// baseline sample right away so cumulative counters start near zero.
func (s *Sampler) SetPID(pid int) {
	atomic.StoreInt32(&s.pid, int32(pid))
	s.lastGPU = ProcessGPUCounters(pid)
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

// hasGPU reports whether a GPU counter set carries any signal.
func hasGPU(c session.HardwareCounters) bool {
	return c.GPUUtilPct > 0 || c.GPUMemUsedMB > 0 || c.GPUPowerW > 0 || c.GPUTempC > 0
}

func (s *Sampler) capture() {
	// Record only while the run's own process is alive, so samples are all
	// per-process and never mixed with a pre-run or post-exit system reading.
	pid := atomic.LoadInt32(&s.pid)
	if pid == 0 || !ProcessAlive(int(pid)) {
		return
	}

	c := ProcessCPUCounters(int(pid))
	// Refresh the slower GPU counters periodically; forward-fill in between.
	if s.tick%gpuRefreshEvery == 0 {
		s.lastGPU = ProcessGPUCounters(int(pid))
	}
	s.tick++
	if hasGPU(s.lastGPU) {
		c.GPUUtilPct = s.lastGPU.GPUUtilPct
		c.GPUMemUsedMB = s.lastGPU.GPUMemUsedMB
		c.GPUPowerW = s.lastGPU.GPUPowerW
		c.GPUTempC = s.lastGPU.GPUTempC
	}

	sample := session.HardwareSample{Timestamp: time.Now().UTC(), Counters: c}
	s.mu.Lock()
	s.samples = append(s.samples, sample)
	s.mu.Unlock()
}

// Decimate evenly reduces a sample series to at most max points, preserving the
// first and last. High-rate sampling gives short runs enough points to judge;
// long runs are thinned here so the signed report stays small without losing the
// fluctuation structure the coherence analysis needs.
func Decimate(samples []session.HardwareSample, max int) []session.HardwareSample {
	n := len(samples)
	if max < 2 || n <= max {
		return samples
	}
	out := make([]session.HardwareSample, 0, max)
	for i := 0; i < max; i++ {
		idx := i * (n - 1) / (max - 1)
		out = append(out, samples[idx])
	}
	return out
}

// Stop terminates sampling and returns all collected samples.
func (s *Sampler) Stop() []session.HardwareSample {
	close(s.stop)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.samples
}

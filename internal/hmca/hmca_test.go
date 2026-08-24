package hmca

import (
	"testing"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

func makeTime(offsetSec int) time.Time {
	base := time.Date(2026, 3, 30, 10, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(offsetSec) * time.Second)
}

func TestZeroCostMetric(t *testing.T) {
	run := &session.RunRecord{
		StartAt:     makeTime(0),
		EndAt:       makeTime(0),
		DurationSec: 0.2,
		Metrics: []session.Metric{
			{Name: "accuracy", Value: 0.95, Source: "explicit"},
		},
	}

	result := Analyze([]*session.RunRecord{run}, nil)

	if result.Verdict == "PASS" && result.Score == 1.0 {
		t.Error("expected HMCA to flag ZERO_COST_METRIC for <1s run with metrics")
	}

	found := false
	for _, f := range result.Flags {
		if containsSubstring(f, "ZERO_COST_METRIC") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ZERO_COST_METRIC flag in result")
	}
}

func TestLowActivityHighGain(t *testing.T) {
	start := makeTime(0)
	end := makeTime(60)
	run := &session.RunRecord{
		StartAt:     start,
		EndAt:       end,
		DurationSec: 60,
		Metrics: []session.Metric{
			{Name: "accuracy", Value: 0.99, Source: "explicit"},
		},
	}

	samples := []session.HardwareSample{
		{Timestamp: makeTime(0), Counters: session.HardwareCounters{CPUTimeSec: 100, MemUsedGB: 2.0}},
		{Timestamp: makeTime(15), Counters: session.HardwareCounters{CPUTimeSec: 100.1, MemUsedGB: 2.0}},
		{Timestamp: makeTime(30), Counters: session.HardwareCounters{CPUTimeSec: 100.2, MemUsedGB: 2.0}},
		{Timestamp: makeTime(45), Counters: session.HardwareCounters{CPUTimeSec: 100.3, MemUsedGB: 2.0}},
		{Timestamp: makeTime(60), Counters: session.HardwareCounters{CPUTimeSec: 100.5, MemUsedGB: 2.0}},
	}

	result := Analyze([]*session.RunRecord{run}, samples)

	found := false
	for _, f := range result.Flags {
		if containsSubstring(f, "LOW_ACTIVITY_HIGH_GAIN") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected LOW_ACTIVITY_HIGH_GAIN flag for high metrics with near-zero CPU")
	}
}

func TestGPUClaimNoGPU(t *testing.T) {
	run := &session.RunRecord{
		StartAt:     makeTime(0),
		EndAt:       makeTime(120),
		DurationSec: 120,
		Hardware: session.HardwareInfo{
			OS:       "linux",
			CPUCores: 8,
			MemGB:    16,
			GPUInfo:  "",
		},
		Phases: []session.PhaseEvent{
			{
				Name: "training",
				Counters: session.HardwareCounters{
					GPUUtilPct: 80,
					GPUMemUsedMB: 4096,
				},
			},
		},
	}

	result := Analyze([]*session.RunRecord{run}, nil)

	found := false
	for _, f := range result.Flags {
		if containsSubstring(f, "GPU_CLAIM_NO_GPU") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GPU_CLAIM_NO_GPU flag when GPU counters present but no GPU in hardware")
	}
}

func TestIdleRun(t *testing.T) {
	start := makeTime(0)
	end := makeTime(120)
	run := &session.RunRecord{
		StartAt:     start,
		EndAt:       end,
		DurationSec: 120,
	}

	samples := []session.HardwareSample{
		{Timestamp: makeTime(0), Counters: session.HardwareCounters{CPUTimeSec: 100}},
		{Timestamp: makeTime(30), Counters: session.HardwareCounters{CPUTimeSec: 100}},
		{Timestamp: makeTime(60), Counters: session.HardwareCounters{CPUTimeSec: 100}},
		{Timestamp: makeTime(90), Counters: session.HardwareCounters{CPUTimeSec: 100}},
		{Timestamp: makeTime(120), Counters: session.HardwareCounters{CPUTimeSec: 100}},
	}

	result := Analyze([]*session.RunRecord{run}, samples)

	found := false
	for _, f := range result.Flags {
		if containsSubstring(f, "IDLE_RUN") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected IDLE_RUN flag when hardware is completely idle for >60s")
	}
}

func TestPhaseMismatch(t *testing.T) {
	// Cumulative CPU: train boundary at 100, eval boundary at 110 (train did 10),
	// then eval runs to a final 200 (eval did 90). Eval work >> train work.
	run := &session.RunRecord{
		StartAt:     makeTime(0),
		EndAt:       makeTime(300),
		DurationSec: 300,
		Phases: []session.PhaseEvent{
			{Name: "training", Counters: session.HardwareCounters{CPUTimeSec: 100}},
			{Name: "evaluation", Counters: session.HardwareCounters{CPUTimeSec: 110}},
		},
		HardwareSamples: []session.HardwareSample{
			{Timestamp: makeTime(0), Counters: session.HardwareCounters{CPUTimeSec: 100}},
			{Timestamp: makeTime(300), Counters: session.HardwareCounters{CPUTimeSec: 200}},
		},
	}

	result := Analyze([]*session.RunRecord{run}, run.HardwareSamples)

	found := false
	for _, f := range result.Flags {
		if containsSubstring(f, "PHASE_MISMATCH") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PHASE_MISMATCH flag when eval uses more CPU than training")
	}
}

func TestCleanPass(t *testing.T) {
	start := makeTime(0)
	end := makeTime(300)
	run := &session.RunRecord{
		StartAt:     start,
		EndAt:       end,
		DurationSec: 300,
		Metrics: []session.Metric{
			{Name: "accuracy", Value: 0.85, Source: "explicit"},
		},
		Hardware: session.HardwareInfo{
			OS:       "linux",
			CPUCores: 8,
			MemGB:    16,
		},
		Phases: []session.PhaseEvent{
			{Name: "training", Counters: session.HardwareCounters{CPUTimeSec: 200}},
			{Name: "evaluation", Counters: session.HardwareCounters{CPUTimeSec: 50}},
		},
	}

	samples := []session.HardwareSample{
		{Timestamp: makeTime(0), Counters: session.HardwareCounters{CPUTimeSec: 0, MemUsedGB: 2.0}},
		{Timestamp: makeTime(100), Counters: session.HardwareCounters{CPUTimeSec: 80, MemUsedGB: 4.5}},
		{Timestamp: makeTime(200), Counters: session.HardwareCounters{CPUTimeSec: 160, MemUsedGB: 5.0}},
		{Timestamp: makeTime(300), Counters: session.HardwareCounters{CPUTimeSec: 230, MemUsedGB: 3.5}},
	}

	result := Analyze([]*session.RunRecord{run}, samples)

	if result.Score != 1.0 {
		t.Errorf("expected perfect score for clean run, got %v (flags: %v)", result.Score, result.Flags)
	}
	if result.Verdict != "PASS" {
		t.Errorf("expected PASS verdict, got %s", result.Verdict)
	}
	if len(result.Flags) != 0 {
		t.Errorf("expected no flags, got %v", result.Flags)
	}
}

func TestScoreClampedAtZero(t *testing.T) {
	// Many flags should not produce negative score
	run := &session.RunRecord{
		StartAt:     makeTime(0),
		EndAt:       makeTime(0),
		DurationSec: 0.1,
		Metrics: []session.Metric{
			{Name: "accuracy", Value: 0.99, Source: "explicit"},
		},
		Hardware: session.HardwareInfo{GPUInfo: ""},
		Phases: []session.PhaseEvent{
			{Name: "training", Counters: session.HardwareCounters{GPUUtilPct: 90, CPUTimeSec: 1}},
			{Name: "evaluation", Counters: session.HardwareCounters{CPUTimeSec: 100}},
		},
	}

	result := Analyze([]*session.RunRecord{run}, nil)

	if result.Score < 0 {
		t.Errorf("score should never be negative, got %v", result.Score)
	}
}

func TestVerdictThresholds(t *testing.T) {
	tests := []struct {
		name     string
		flagCnt  int
		wantVerdict string
	}{
		{"no_flags", 0, "PASS"},
		{"two_flags", 2, "PASS"},
		{"three_flags", 3, "WARN"},
		{"six_flags", 6, "FAIL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score := 1.0 - float64(tc.flagCnt)*0.1
			if score < 0 {
				score = 0
			}
			var verdict string
			if score < 0.5 {
				verdict = "FAIL"
			} else if score < 0.8 {
				verdict = "WARN"
			} else {
				verdict = "PASS"
			}
			if verdict != tc.wantVerdict {
				t.Errorf("score=%.1f: got verdict %s, want %s", score, verdict, tc.wantVerdict)
			}
		})
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

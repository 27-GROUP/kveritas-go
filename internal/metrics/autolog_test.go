package metrics

import (
	"fmt"
	"testing"
)

func TestAutoFormats(t *testing.T) {
	cases := []struct {
		lines []string
		want  []string
	}{
		{[]string{"{'loss': 0.2103, 'grad_norm': 1.2, 'learning_rate': 5e-05, 'epoch': 1.0}"},
			[]string{"loss=0.2103 step=1.0 auto:trainer"}},
		{[]string{"{'eval_loss': 0.31, 'eval_accuracy': 0.912, 'epoch': 3.0}"},
			[]string{"eval_loss=0.31 step=3.0 auto:trainer", "eval_accuracy=0.912 step=3.0 auto:trainer"}},
		{[]string{`{"step": 4, "acc": 0.93}`}, []string{"acc=0.93 step=4 auto:json"}},
		{[]string{"Epoch 3/10", "938/938 - 3s - 3ms/step - accuracy: 0.9312 - loss: 0.2103 - val_accuracy: 0.9100"},
			[]string{"accuracy=0.9312 step=3 auto:keras", "loss=0.2103 step=3 auto:keras", "val_accuracy=0.91 step=3 auto:keras"}},
		{[]string{"Epoch 2: 100%|██████████| 938/938 [00:05<00:00, 160.51it/s, v_num=0, loss=0.21, val_acc=0.93]"},
			[]string{"loss=0.21 step=2 auto:lightning", "val_acc=0.93 step=2 auto:lightning"}},
		{[]string{"[50]\tvalidation_0-logloss:0.21234\tvalidation_1-auc:0.9"},
			[]string{"validation_0_logloss=0.21234 step=50 auto:xgboost", "validation_1_auc=0.9 step=50 auto:xgboost"}},
		{[]string{"[100]\tvalid_0's auc: 0.93\tvalid_0's binary_logloss: 0.2"},
			[]string{"valid_0_auc=0.93 step=100 auto:lightgbm", "valid_0_binary_logloss=0.2 step=100 auto:lightgbm"}},
		{[]string{"Benchmark 1: sort big.txt", "  Time (mean ± σ):     101.3 ms ±   0.4 ms    [User: 90.1 ms, System: 10.2 ms]"},
			[]string{"bench1_time_mean_ms=101.3 step= auto:hyperfine"}},
		{[]string{"BM_Sort/1024        12345 ns        12300 ns        56789"},
			[]string{"bm_sort_1024_time_ns=12345 step= auto:gbench", "bm_sort_1024_cpu_ns=12300 step= auto:gbench"}},
		{[]string{"fib 20                  time:   [24.141 µs 24.300 µs 24.452 µs]"},
			[]string{"fib_20_time_us=24.3 step= auto:criterion"}},
		{[]string{"real\t0m1.234s"}, []string{"real_time_s=1.234 step= auto:time"}},
		{[]string{"throughput: 12.4 Gb/s"}, []string{"throughput_gb_s=12.4 step= auto:line"}},
		{[]string{"Solve time: 3.2 s"}, []string{"solve_time_s=3.2 step= auto:line"}},
		{[]string{"seed: 42", "epoch: 3", "Loading data...", "KV cache size: 2GB"}, nil},
	}
	for _, c := range cases {
		a := &Auto{}
		var got []string
		for i, l := range c.lines {
			for _, m := range a.Line(l, i+1) {
				got = append(got, fmt.Sprintf("%s=%g step=%s %s", m.Name, m.Value, m.Step, m.Source))
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%q:\n got  %v\n want %v", c.lines, got, c.want)
		}
	}
}

package metrics

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func pbVarint(num int, v uint64) []byte {
	b := binary.AppendUvarint(nil, uint64(num<<3))
	return binary.AppendUvarint(b, v)
}

func pbBytes(num int, v []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(num<<3|2))
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func pbFloat(num int, v float32) []byte {
	b := binary.AppendUvarint(nil, uint64(num<<3|5))
	return binary.LittleEndian.AppendUint32(b, math.Float32bits(v))
}

func tfRecord(data []byte) []byte {
	b := binary.LittleEndian.AppendUint64(nil, uint64(len(data)))
	b = append(b, 0, 0, 0, 0)
	b = append(b, data...)
	return append(b, 0, 0, 0, 0)
}

func TestAutoFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, []byte(content), 0644)
	}
	write("out/trainer_state.json", `{"log_history": [{"loss": 0.5, "learning_rate": 5e-5, "step": 100}, {"eval_accuracy": 0.91, "step": 100}]}`)
	write("logs/metrics.csv", "epoch,step,val_acc\n0,10,0.71\n1,20,0.83\n")
	write("mlruns/0/abc/metrics/rmse", "1700000000000 0.42 0\n1700000001000 0.38 1\n")

	simple := pbBytes(1, append(pbBytes(1, []byte("train/loss")), pbFloat(2, 0.25)...))
	tensor := pbBytes(1, append(pbBytes(1, []byte("val/top1")), pbBytes(8, append(pbVarint(1, 1), pbFloat(5, 0.875)...))...))
	var events []byte
	events = append(events, tfRecord(append(pbVarint(2, 7), pbBytes(5, simple)...))...)
	events = append(events, tfRecord(append(pbVarint(2, 8), pbBytes(5, tensor)...))...)
	write("runs/a/events.out.tfevents.1.host", string(events))

	got := map[string]string{}
	for _, m := range AutoFiles(dir, time.Now().Add(-time.Minute)) {
		got[m.Name] = m.Source + " " + m.Step + " " + formatFloat(m.Value)
	}
	want := map[string]string{
		"loss":          "auto:trainer_state 100 0.5",
		"eval_accuracy": "auto:trainer_state 100 0.91",
		"val_acc":       "auto:csv 20 0.83",
		"rmse":          "auto:mlflow 1 0.38",
		"train_loss":    "auto:tensorboard 7 0.25",
		"val_top1":      "auto:tensorboard 8 0.875",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	if len(AutoFiles(dir, time.Now().Add(time.Hour))) != 0 {
		t.Error("files from before the run were read")
	}
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

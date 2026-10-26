package metrics

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

var skipDirs = map[string]bool{
	".git": true, ".kveritas": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, "site-packages": true, ".tox": true, ".mypy_cache": true,
}

const (
	maxScanned   = 20000
	maxFileSize  = 256 << 20
	pointsPerTag = 50
)

func AutoFiles(root string, since time.Time) []session.Metric {
	var out []session.Metric
	scanned := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if scanned++; scanned > maxScanned {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || info.ModTime().Before(since) || info.Size() > maxFileSize {
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasPrefix(name, "events.out.tfevents."):
			out = append(out, thin(tensorboard(path))...)
		case name == "trainer_state.json":
			out = append(out, trainerState(path)...)
		case name == "metrics.csv" || name == "training.log":
			out = append(out, csvLog(path)...)
		case filepath.Base(filepath.Dir(path)) == "metrics" && strings.Contains(path, "mlruns"):
			out = append(out, mlflowMetric(path, name)...)
		}
		return nil
	})
	return out
}

func metric(name string, v float64, step, source string) (session.Metric, bool) {
	name = cleanName(name)
	if name == "" || notResults[name] || math.IsNaN(v) || math.IsInf(v, 0) {
		return session.Metric{}, false
	}
	return session.Metric{Name: name, Value: v, Step: step, Source: "auto:" + source}, true
}

func thin(ms []session.Metric) []session.Metric {
	byName := map[string][]session.Metric{}
	var order []string
	for _, m := range ms {
		if _, ok := byName[m.Name]; !ok {
			order = append(order, m.Name)
		}
		byName[m.Name] = append(byName[m.Name], m)
	}
	var out []session.Metric
	for _, n := range order {
		s := byName[n]
		if len(s) <= pointsPerTag {
			out = append(out, s...)
			continue
		}
		for i := 0; i < pointsPerTag; i++ {
			out = append(out, s[i*(len(s)-1)/(pointsPerTag-1)])
		}
	}
	return out
}

func trainerState(path string) []session.Metric {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st struct {
		LogHistory []map[string]any `json:"log_history"`
	}
	if json.Unmarshal(data, &st) != nil {
		return nil
	}
	var out []session.Metric
	for _, entry := range st.LogHistory {
		step := ""
		if s, ok := entry["step"].(float64); ok {
			step = strconv.FormatFloat(s, 'g', -1, 64)
		}
		keys := make([]string, 0, len(entry))
		for k := range entry {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if v, ok := entry[k].(float64); ok {
				if m, ok := metric(k, v, step, "trainer_state"); ok {
					out = append(out, m)
				}
			}
		}
	}
	return thin(out)
}

func csvLog(path string) []session.Metric {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	head, err := r.Read()
	if err != nil {
		return nil
	}
	stepCol := -1
	for i, h := range head {
		if h == "step" || (h == "epoch" && stepCol < 0) {
			stepCol = i
		}
	}
	var out []session.Metric
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		step := ""
		if stepCol >= 0 && stepCol < len(row) {
			step = row[stepCol]
		}
		for i, cell := range row {
			if i >= len(head) || cell == "" {
				continue
			}
			if v, err := strconv.ParseFloat(cell, 64); err == nil {
				if m, ok := metric(head[i], v, step, "csv"); ok {
					out = append(out, m)
				}
			}
		}
	}
	return thin(out)
}

func mlflowMetric(path, name string) []session.Metric {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []session.Metric
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fs[1], 64)
		if err != nil {
			continue
		}
		step := ""
		if len(fs) > 2 {
			step = fs[2]
		}
		if m, ok := metric(name, v, step, "mlflow"); ok {
			out = append(out, m)
		}
	}
	return thin(out)
}

func tensorboard(path string) []session.Metric {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var out []session.Metric
	for {
		var hdr [12]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			break
		}
		n := binary.LittleEndian.Uint64(hdr[:8])
		if n > 64<<20 {
			break
		}
		rec := make([]byte, n+4)
		if _, err := io.ReadFull(r, rec); err != nil {
			break
		}
		step, values := parseEvent(rec[:n])
		for _, v := range values {
			if m, ok := metric(v.tag, v.value, strconv.FormatInt(step, 10), "tensorboard"); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

type scalar struct {
	tag   string
	value float64
}

type field struct {
	num  int
	wire int
	u    uint64
	b    []byte
}

func fields(b []byte) []field {
	var out []field
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return out
		}
		b = b[n:]
		f := field{num: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return out
			}
			f.u, b = v, b[n:]
		case 1:
			if len(b) < 8 {
				return out
			}
			f.u, b = binary.LittleEndian.Uint64(b), b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return out
			}
			f.b, b = b[n:n+int(l)], b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return out
			}
			f.u, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		default:
			return out
		}
		out = append(out, f)
	}
	return out
}

func parseEvent(b []byte) (int64, []scalar) {
	var step int64
	var out []scalar
	for _, f := range fields(b) {
		switch {
		case f.num == 2 && f.wire == 0:
			step = int64(f.u)
		case f.num == 5 && f.wire == 2:
			for _, v := range fields(f.b) {
				if v.num == 1 && v.wire == 2 {
					if s, ok := parseValue(v.b); ok {
						out = append(out, s)
					}
				}
			}
		}
	}
	return step, out
}

func parseValue(b []byte) (scalar, bool) {
	var s scalar
	found := false
	for _, f := range fields(b) {
		switch {
		case f.num == 1 && f.wire == 2:
			s.tag = string(f.b)
		case f.num == 2 && f.wire == 5:
			s.value, found = f32(math.Float32frombits(uint32(f.u))), true
		case f.num == 8 && f.wire == 2:
			if v, ok := tensorScalar(f.b); ok {
				s.value, found = v, true
			}
		}
	}
	return s, found && s.tag != ""
}

func tensorScalar(b []byte) (float64, bool) {
	dtype := 0
	for _, f := range fields(b) {
		if f.num == 1 && f.wire == 0 {
			dtype = int(f.u)
		}
	}
	for _, f := range fields(b) {
		switch {
		case f.num == 5 && f.wire == 5:
			return f32(math.Float32frombits(uint32(f.u))), true
		case f.num == 5 && f.wire == 2 && len(f.b) >= 4:
			return f32(math.Float32frombits(binary.LittleEndian.Uint32(f.b))), true
		case f.num == 6 && f.wire == 1:
			return math.Float64frombits(f.u), true
		case f.num == 6 && f.wire == 2 && len(f.b) >= 8:
			return math.Float64frombits(binary.LittleEndian.Uint64(f.b)), true
		case f.num == 4 && f.wire == 2:
			if dtype == 2 && len(f.b) == 8 {
				return math.Float64frombits(binary.LittleEndian.Uint64(f.b)), true
			}
			if len(f.b) == 4 {
				return f32(math.Float32frombits(binary.LittleEndian.Uint32(f.b))), true
			}
		}
	}
	return 0, false
}

func f32(v float32) float64 {
	f, _ := strconv.ParseFloat(strconv.FormatFloat(float64(v), 'g', -1, 32), 64)
	return f
}

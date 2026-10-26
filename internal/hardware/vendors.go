package hardware

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rocm-smi --json renames fields across releases, so values are found by key fragments.
func rocmField(fields map[string]string, parts ...string) (string, bool) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lk := strings.ToLower(k)
		match := true
		for _, p := range parts {
			if !strings.Contains(lk, p) {
				match = false
				break
			}
		}
		if match {
			return fields[k], true
		}
	}
	return "", false
}

func rocmNumber(fields map[string]string, parts ...string) float64 {
	v, ok := rocmField(fields, parts...)
	if !ok {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(v, "%")), 64)
	return f
}

func parseRocmCards(data []byte) (cards []map[string]string, system map[string]string) {
	var raw map[string]map[string]string
	if json.Unmarshal(data, &raw) != nil {
		return nil, nil
	}
	names := make([]string, 0, len(raw))
	for k := range raw {
		if strings.HasPrefix(strings.ToLower(k), "card") {
			names = append(names, k)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(strings.ToLower(names[i]), "card"))
		b, _ := strconv.Atoi(strings.TrimPrefix(strings.ToLower(names[j]), "card"))
		return a < b
	})
	for _, n := range names {
		cards = append(cards, raw[n])
	}
	return cards, raw["system"]
}

func parseRocmCounters(data []byte) gpuState {
	g := gpuState{}
	cards, _ := parseRocmCards(data)
	for _, c := range cards {
		g.GPUUtilPct += rocmNumber(c, "gpu use")
		g.GPUMemUsedMB += rocmNumber(c, "vram", "used memory") / 1e6
		g.GPUPowerW += rocmNumber(c, "power (w)")
		t := rocmNumber(c, "temperature", "edge")
		if t == 0 {
			t = rocmNumber(c, "temperature")
		}
		if t > g.GPUTempC {
			g.GPUTempC = t
		}
	}
	return g
}

func parseRocmInventory(data []byte) []GPU {
	cards, system := parseRocmCards(data)
	driver, _ := rocmField(system, "driver version")
	var out []GPU
	for i, c := range cards {
		name, ok := rocmField(c, "card series")
		if !ok {
			name, _ = rocmField(c, "card model")
		}
		uuid, _ := rocmField(c, "unique id")
		out = append(out, GPU{
			Index:    i,
			Vendor:   "AMD",
			Name:     strings.TrimSpace(name),
			UUID:     strings.TrimSpace(uuid),
			MemoryMB: rocmNumber(c, "vram total memory") / 1e6,
			Driver:   strings.TrimSpace(driver),
		})
	}
	return out
}

func parseRocmPIDs(data []byte) map[int]float64 {
	var raw map[string]map[string]string
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}
	out := map[int]float64{}
	for k, v := range raw["system"] {
		pid, err := strconv.Atoi(strings.TrimPrefix(k, "PID"))
		if err != nil {
			continue
		}
		f := strings.Split(v, ",")
		if len(f) < 3 {
			continue
		}
		b, _ := strconv.ParseFloat(strings.TrimSpace(f[2]), 64)
		out[pid] = b / 1e6
	}
	return out
}

func amdCounters() (gpuState, bool) {
	out, err := exec.Command("rocm-smi", "--showuse", "--showpower", "--showtemp", "--showmeminfo", "vram", "--json").Output()
	if err != nil {
		return gpuState{}, false
	}
	return parseRocmCounters(out), true
}

func amdInventory() []GPU {
	out, err := exec.Command("rocm-smi", "--showproductname", "--showmeminfo", "vram", "--showdriverversion", "--showuniqueid", "--json").Output()
	if err != nil {
		return nil
	}
	return parseRocmInventory(out)
}

func amdMemForPIDs(pids map[int]bool) (float64, bool) {
	out, err := exec.Command("rocm-smi", "--showpids", "--json").Output()
	if err != nil {
		return 0, false
	}
	total := 0.0
	for pid, mb := range parseRocmPIDs(out) {
		if pids[pid] {
			total += mb
		}
	}
	return total, true
}

var (
	ioregUtilRe = regexp.MustCompile(`"Device Utilization %"\s*=\s*(\d+)`)
	ioregMemRe  = regexp.MustCompile(`"In use system memory"\s*=\s*(\d+)`)
)

func parseIoreg(data []byte) gpuState {
	g := gpuState{}
	for _, m := range ioregUtilRe.FindAllSubmatch(data, -1) {
		v, _ := strconv.ParseFloat(string(m[1]), 64)
		g.GPUUtilPct += v
	}
	for _, m := range ioregMemRe.FindAllSubmatch(data, -1) {
		v, _ := strconv.ParseFloat(string(m[1]), 64)
		g.GPUMemUsedMB += v / 1e6
	}
	return g
}

func appleCounters() (gpuState, bool) {
	out, err := exec.Command("ioreg", "-r", "-d", "1", "-w", "0", "-c", "IOAccelerator").Output()
	if err != nil || !ioregUtilRe.Match(out) {
		return gpuState{}, false
	}
	return parseIoreg(out), true
}

func parseSystemProfiler(data []byte) []GPU {
	var doc struct {
		Displays []struct {
			Model  string `json:"sppci_model"`
			Cores  string `json:"sppci_cores"`
			Vendor string `json:"spdisplays_vendor"`
		} `json:"SPDisplaysDataType"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []GPU
	for i, d := range doc.Displays {
		vendor := strings.TrimPrefix(d.Vendor, "sppci_vendor_")
		g := GPU{Index: i, Vendor: vendor, Name: d.Model}
		if n, err := strconv.Atoi(d.Cores); err == nil {
			g.Cores = n
		}
		out = append(out, g)
	}
	return out
}

func appleInventory() []GPU {
	out, err := exec.Command("system_profiler", "SPDisplaysDataType", "-json").Output()
	if err != nil {
		return nil
	}
	return parseSystemProfiler(out)
}

func parsePSTime(s string) float64 {
	days := 0.0
	if d, rest, ok := strings.Cut(s, "-"); ok {
		days, _ = strconv.ParseFloat(d, 64)
		s = rest
	}
	total := 0.0
	for _, p := range strings.Split(s, ":") {
		v, _ := strconv.ParseFloat(p, 64)
		total = total*60 + v
	}
	return days*86400 + total
}

type psRow struct {
	ppid  int
	cpu   float64
	rssKB float64
}

func parsePS(data []byte) map[int]psRow {
	out := map[int]psRow{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		rss, _ := strconv.ParseFloat(f[3], 64)
		out[pid] = psRow{ppid: ppid, cpu: parsePSTime(f[2]), rssKB: rss}
	}
	return out
}

func treeOf(rows map[int]psRow, root, exclude int) map[int]bool {
	tree := map[int]bool{root: true}
	for changed := true; changed; {
		changed = false
		for pid, r := range rows {
			if !tree[pid] && pid != exclude && tree[r.ppid] {
				tree[pid] = true
				changed = true
			}
		}
	}
	return tree
}

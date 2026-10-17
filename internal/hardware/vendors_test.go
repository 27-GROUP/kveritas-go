package hardware

import (
	"math"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestRocmCounters(t *testing.T) {
	data := []byte(`{
	  "card0": {"Temperature (Sensor edge) (C)": "45.0", "Temperature (Sensor junction) (C)": "50.0",
	            "Average Graphics Package Power (W)": "120.0", "GPU use (%)": "80",
	            "VRAM Total Memory (B)": "68702699520", "VRAM Total Used Memory (B)": "34351349760"},
	  "card1": {"Temperature (Sensor edge) (C)": "55.0", "Current Socket Graphics Package Power (W)": "100.0",
	            "GPU use (%)": "60", "VRAM Total Memory (B)": "68702699520", "VRAM Total Used Memory (B)": "1000000000"}
	}`)
	g := parseRocmCounters(data)
	if !near(g.GPUUtilPct, 140) || !near(g.GPUPowerW, 220) || !near(g.GPUTempC, 55) || !near(g.GPUMemUsedMB, 35351.34976) {
		t.Fatalf("got %+v", g)
	}
}

func TestRocmInventory(t *testing.T) {
	data := []byte(`{
	  "card0": {"Card series": "AMD Instinct MI210", "Card model": "0x0740", "Unique ID": "0x1234",
	            "VRAM Total Memory (B)": "68702699520"},
	  "card1": {"Card Series": "AMD Instinct MI210", "VRAM Total Memory (B)": "68702699520"},
	  "system": {"Driver version": "6.2.4"}
	}`)
	gpus := parseRocmInventory(data)
	if len(gpus) != 2 || gpus[0].Name != "AMD Instinct MI210" || gpus[1].Name != "AMD Instinct MI210" ||
		gpus[0].Driver != "6.2.4" || gpus[0].UUID != "0x1234" || gpus[0].Vendor != "AMD" || !near(gpus[0].MemoryMB, 68702.69952) {
		t.Fatalf("got %+v", gpus)
	}
}

func TestRocmPIDs(t *testing.T) {
	m := parseRocmPIDs([]byte(`{"system": {"PID4242": "python3, 1, 2147483648, 0, 0", "PID999": "other, 1, 100, 0, 0"}}`))
	if len(m) != 2 || !near(m[4242], 2147.483648) {
		t.Fatalf("got %v", m)
	}
}

func TestIoreg(t *testing.T) {
	data := []byte(`+-o AGXAcceleratorG14X  <class AGXAcceleratorG14X>
    | "PerformanceStatistics" = {"In use system memory"=1073741824,"Device Utilization %"=37,"Tiler Utilization %"=30}`)
	g := parseIoreg(data)
	if !near(g.GPUUtilPct, 37) || !near(g.GPUMemUsedMB, 1073.741824) {
		t.Fatalf("got %+v", g)
	}
}

func TestSystemProfiler(t *testing.T) {
	gpus := parseSystemProfiler([]byte(`{"SPDisplaysDataType":[{"sppci_model":"Apple M2 Pro","sppci_cores":"19","spdisplays_vendor":"sppci_vendor_Apple"}]}`))
	if len(gpus) != 1 || gpus[0].Name != "Apple M2 Pro" || gpus[0].Cores != 19 || gpus[0].Vendor != "Apple" {
		t.Fatalf("got %+v", gpus)
	}
}

func TestPSTree(t *testing.T) {
	rows := parsePS([]byte("  1     0   0:01.50  1024\n 100   1   1:02.25  2048\n 200 100   0:00.25  4096\n 250 200   0:03.00  10\n 300   1   1-02:00:00  10\n"))
	if !near(rows[100].cpu, 62.25) || !near(rows[300].cpu, 93600) {
		t.Fatalf("times %+v", rows)
	}
	tree := treeOf(rows, 100, 250)
	if len(tree) != 2 || !tree[100] || !tree[200] || tree[250] {
		t.Fatalf("tree %v", tree)
	}
}

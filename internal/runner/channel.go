package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// ChannelEnv names the variable that tells an SDK where the private result channel is.
const ChannelEnv = "KVERITAS_CHANNEL"

const cellDir = ".kveritas_cells"

type channelMessage struct {
	Seq            int             `json:"seq"`
	Kind           string          `json:"kind"`
	Name           string          `json:"name,omitempty"`
	Metric         string          `json:"metric,omitempty"`
	Value          json.RawMessage `json:"value,omitempty"`
	Step           json.RawMessage `json:"step,omitempty"`
	Phase          string          `json:"phase,omitempty"`
	Params         int64           `json:"params,omitempty"`
	Arch           string          `json:"arch,omitempty"`
	Precision      string          `json:"precision,omitempty"`
	DatasetSize    int64           `json:"dataset_size,omitempty"`
	Epochs         float64         `json:"epochs,omitempty"`
	BatchSize      int64           `json:"batch_size,omitempty"`
	SeqLen         int64           `json:"seq_len,omitempty"`
	Role           string          `json:"role,omitempty"`
	Path           string          `json:"path,omitempty"`
	Visibility     string          `json:"visibility,omitempty"`
	ExecCount      int             `json:"exec_count,omitempty"`
	Source         string          `json:"source,omitempty"`
	WorldSize      int             `json:"world_size,omitempty"`
	LocalWorldSize int             `json:"local_world_size,omitempty"`
	Nodes          int             `json:"nodes,omitempty"`
	Launcher       string          `json:"launcher,omitempty"`
	ExitCode       *int            `json:"exit_code,omitempty"`
}

func rawText(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	return string(r)
}

func numText(r json.RawMessage) (string, bool) {
	var f float64
	if err := json.Unmarshal(r, &f); err != nil {
		return "", false
	}
	return strconv.FormatFloat(f, 'g', -1, 64), true
}

func token(s string) string {
	return strings.Join(strings.Fields(s), "_")
}

// A message becomes the protocol line it stands for, so it is parsed and validated
// exactly like printed output.
func (m *channelMessage) line() string {
	switch m.Kind {
	case "metric":
		v, ok := numText(m.Value)
		if !ok {
			return ""
		}
		l := fmt.Sprintf("KVERITAS_METRIC name=%s value=%s", m.Name, v)
		if step := token(rawText(m.Step)); step != "" {
			l += " step=" + step
		}
		return l
	case "phase":
		return "KVERITAS_PHASE name=" + token(m.Name)
	case "claim":
		v, ok := numText(m.Value)
		if !ok {
			return ""
		}
		l := fmt.Sprintf("KVERITAS_CLAIM metric=%s value=%s", m.Metric, v)
		if m.Phase != "" {
			l += " phase=" + token(m.Phase)
		}
		return l
	case "seed":
		if v := token(rawText(m.Value)); v != "" {
			return "KVERITAS_INPUT src=seed:" + v
		}
	case "model":
		return fmt.Sprintf("KVERITAS_MODEL params=%d arch=%s precision=%s", m.Params, token(m.Arch), token(m.Precision))
	case "workload":
		l := fmt.Sprintf("KVERITAS_WORKLOAD dataset_size=%d epochs=%s batch_size=%d",
			m.DatasetSize, strconv.FormatFloat(m.Epochs, 'g', -1, 64), m.BatchSize)
		if m.SeqLen > 0 {
			l += fmt.Sprintf(" seq_len=%d", m.SeqLen)
		}
		return l
	case "artifact":
		l := fmt.Sprintf("KVERITAS_ARTIFACT role=%s path=%s visibility=%s", token(m.Role), token(m.Path), token(m.Visibility))
		if m.Name != "" {
			l += " name=" + token(m.Name)
		}
		return l
	}
	return ""
}

func (m *channelMessage) distributed() *session.Distributed {
	if m.WorldSize <= 1 && m.Nodes <= 1 {
		return nil
	}
	return &session.Distributed{
		WorldSize:      m.WorldSize,
		LocalWorldSize: m.LocalWorldSize,
		Nodes:          m.Nodes,
		Launcher:       m.Launcher,
	}
}

// Cells are written into the project so provenance snapshots and the open bundle
// carry the exact code a notebook executed, in execution order.
func (m *channelMessage) cell(projectDir string) (session.NotebookCell, error) {
	c := session.NotebookCell{
		ExecCount: m.ExecCount,
		Hash:      crypto.HashBytes([]byte(m.Source)),
		Seq:       m.Seq,
		Timestamp: time.Now().UTC(),
	}
	dir := filepath.Join(projectDir, cellDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return c, err
	}
	name := fmt.Sprintf("cell_%04d_%04d.py", m.Seq, m.ExecCount)
	return c, os.WriteFile(filepath.Join(dir, name), []byte(m.Source), 0644)
}

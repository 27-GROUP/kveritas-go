package metrics

import (
	"reflect"
	"testing"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

func TestTranslateKV(t *testing.T) {
	cases := []struct {
		line     string
		want     []string
		ok, near bool
	}{
		{"KV val_acc=0.93 loss=0.21 step=3", []string{
			"KVERITAS_METRIC name=val_acc value=0.93 step=3",
			"KVERITAS_METRIC name=loss value=0.21 step=3"}, true, false},
		{"KV acc=1e-3", []string{"KVERITAS_METRIC name=acc value=0.001"}, true, false},
		{"KV claim test_acc=0.91 phase=eval", []string{"KVERITAS_CLAIM metric=test_acc value=0.91 phase=eval"}, true, false},
		{"KV seed 42", []string{"KVERITAS_INPUT src=seed:42"}, true, false},
		{"KV phase train", []string{"KVERITAS_PHASE name=train"}, true, false},
		{"KV model params=25.6e6 arch=resnet50", []string{"KVERITAS_MODEL params=25.6e6 arch=resnet50"}, true, false},
		{"KV cache size=2GB", nil, false, true},
		{"KV cache: 2048 MB", nil, false, true},
		{"KV acc=high", nil, false, true},
		{"KV", nil, false, true},
		{"KVcache=1", nil, false, false},
		{"loss=0.2", nil, false, false},
		{"KVERITAS_METRIC name=a value=1", nil, false, false},
	}
	for _, c := range cases {
		got, ok, near := TranslateKV(c.line)
		if !reflect.DeepEqual(got, c.want) || ok != c.ok || near != c.near {
			t.Errorf("%q: got %v ok=%v near=%v", c.line, got, ok, near)
		}
	}
	for _, c := range cases {
		lines, ok, _ := TranslateKV(c.line)
		if !ok {
			continue
		}
		p := &Parser{}
		for _, l := range lines {
			_, m := p.Parse(l, 1)
			_, cl := p.ParseClaim(l, 1)
			_, s := p.ParseSeed(l)
			_, ph := p.ParsePhase(l)
			if !m && !cl && !s && !ph && !p.ParseDeclared(l, &session.DeclaredModel{}) {
				t.Errorf("%q: translated line %q not accepted by the parser", c.line, l)
			}
		}
	}
}

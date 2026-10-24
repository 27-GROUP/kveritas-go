package provenance

import (
	"os"
	"syscall"
)

func fileIdentity(st os.FileInfo) (uint64, int64) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return uint64(s.Ino), s.Ctim.Nano()
}

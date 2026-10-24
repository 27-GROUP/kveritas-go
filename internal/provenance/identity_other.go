//go:build !linux && !darwin

package provenance

import "os"

func fileIdentity(os.FileInfo) (uint64, int64) { return 0, 0 }

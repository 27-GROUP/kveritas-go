//go:build !linux && !darwin

package provenance

import "errors"

func cloneFile(src, dst string) error { return errors.ErrUnsupported }

package provenance

import "golang.org/x/sys/unix"

// A copy-on-write clone (APFS): instant, and no extra space until one side changes.
func cloneFile(src, dst string) error {
	return unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW)
}

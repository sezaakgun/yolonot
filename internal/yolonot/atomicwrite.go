package yolonot

import (
	"fmt"
	"os"
	"path/filepath"
)

// atomicWriteFile writes data to path via a same-directory temp file and a
// rename, refusing to follow symlinks at the target. This is the standard
// defense against the two failure modes that plain os.WriteFile has when
// the target dir is user-writable but shared with an attacker-controlled
// process:
//
//  1. TOCTOU symlink: an attacker replaces path with a symlink pointing
//     at /etc/cron.d/malicious between our Stat and our Write; plain
//     os.WriteFile (O_WRONLY|O_CREAT|O_TRUNC) happily follows the symlink
//     and we write content the attacker controls where they want it.
//     atomicWriteFile does an explicit Lstat and refuses to rename over
//     a pre-existing symlink.
//  2. Partial-write: a crash mid-write leaves the target truncated.
//     Rename is atomic on a single filesystem, so either the pre-write
//     contents or the full post-write contents are observable — never a
//     partial file.
//
// The mode is applied both at tempfile creation and again post-rename via
// Chmod, because some filesystems strip suid/guid bits on rename and some
// umasks mask the mode at create time.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// Refuse to overwrite a symlink. A pre-existing regular file is fine —
	// rename replaces it atomically.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink at %s", path)
		}
	}
	tmp, err := os.CreateTemp(dir, ".yolonot-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we fail mid-flight.
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	// rename can silently widen perms on some filesystems; enforce again.
	os.Chmod(path, perm)
	return nil
}

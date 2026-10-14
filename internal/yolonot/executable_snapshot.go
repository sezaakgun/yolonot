package yolonot

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Native executable snapshots are local approval evidence only. Binary bytes
// are never attached to model prompts or added to the classifier script cache.
const maxExecutableSnapshotBytes = 64 << 20

func executableApprovalPrefix(command string) string {
	return fmt.Sprintf("executable:%x:", sha256.Sum256([]byte(command)))
}

func nativeExecutableIdentity(command, cwd string) (identity, token string) {
	if !isInertCommand(command) {
		return "", ""
	}
	words := strings.Fields(command)
	if len(words) == 0 || !strings.Contains(words[0], "/") {
		return "", ""
	}
	token = words[0]
	path := token
	if !filepath.IsAbs(path) {
		path = cwd + string(filepath.Separator) + path
	}
	if isSensitivePath(path) {
		return "", token
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || isSensitivePath(resolved) {
		return "", token
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", token
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0111 == 0 || before.Size() > maxExecutableSnapshotBytes {
		return "", token
	}
	var magic [4]byte
	if _, err = io.ReadFull(f, magic[:]); err != nil || !nativeExecutableMagic(magic) {
		return "", token
	}
	h := sha256.New()
	h.Write(magic[:])
	n, err := io.Copy(h, io.LimitReader(f, maxExecutableSnapshotBytes-3))
	if err != nil || n+4 > maxExecutableSnapshotBytes {
		return "", token
	}
	after, err := f.Stat()
	if err != nil || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() || n+4 != after.Size() {
		return "", token
	}
	current, err := os.Stat(path)
	if err != nil || !os.SameFile(after, current) {
		return "", token
	}
	currentPath, err := filepath.EvalSymlinks(path)
	if err != nil || currentPath != resolved {
		return "", token
	}
	// Include resolved target and execution mode; changing a symlink target or
	// making the file non-executable cannot retain an earlier grant.
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%x", resolved, after.Mode(), h.Sum(nil))))), token
}

func nativeExecutableMagic(m [4]byte) bool {
	if m == [4]byte{0x7f, 'E', 'L', 'F'} {
		return true
	}
	switch binary.BigEndian.Uint32(m[:]) {
	case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca:
		return true
	}
	return false
}

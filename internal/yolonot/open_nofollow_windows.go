//go:build windows

package yolonot

import (
	"fmt"
	"os"
)

func openReadOnlyNoFollow(path string) (*os.File, error) {
	lfi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if lfi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink %s", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !os.SameFile(lfi, fi) {
		f.Close()
		return nil, fmt.Errorf("file changed during open %s", path)
	}
	return f, nil
}

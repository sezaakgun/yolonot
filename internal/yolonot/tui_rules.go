package yolonot

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
)

// Rule editors use temporary files just like the config editors. The
// active files are touched only when the settings page is saved.
type ruleDraft struct {
	original, data []byte
	existed        bool
	mode           os.FileMode
}

type ruleDrafts struct {
	files map[string]ruleDraft
}

var tuiRuleDrafts *ruleDrafts

func readRuleDraft(path string) (ruleDraft, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ruleDraft{mode: 0600}, nil
	}
	if err != nil {
		return ruleDraft{}, err
	}
	if !info.Mode().IsRegular() {
		return ruleDraft{}, fmt.Errorf("rules must be a regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	return ruleDraft{original: data, data: data, existed: true, mode: info.Mode().Perm()}, err
}

func (d *ruleDrafts) edit(path string) (bool, error) {
	draft, ok := d.files[path]
	if !ok {
		var err error
		draft, err = readRuleDraft(path)
		if err != nil {
			return false, err
		}
	}
	text, ok := editText("yolonot-rules-*.txt", string(draft.data))
	if !ok {
		return false, nil
	}
	draft.data = []byte(text)
	if bytes.Equal(draft.data, draft.original) {
		delete(d.files, path)
		return false, nil
	}
	if d.files == nil {
		d.files = make(map[string]ruleDraft)
	}
	d.files[path] = draft
	return true, nil
}

func (d *ruleDrafts) dirty() bool { return d != nil && len(d.files) > 0 }

// commit returns a rollback operation for a subsequent config save
// failure. Detect external edits before writing instead of silently
// replacing policy changed while this settings page was open.
func (d *ruleDrafts) commit() (func() error, error) {
	var paths []string
	if d != nil {
		for path := range d.files {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		current, err := readRuleDraft(path)
		if err != nil {
			return nil, err
		}
		draft := d.files[path]
		if current.existed != draft.existed || !bytes.Equal(current.original, draft.original) {
			return nil, fmt.Errorf("rules changed outside settings; reopen settings before saving: %s", path)
		}
	}
	var written []string
	rollback := func() error {
		var errs []error
		for i := len(written) - 1; i >= 0; i-- {
			path := written[i]
			draft := d.files[path]
			var err error
			if draft.existed {
				err = atomicWriteFile(path, draft.original, draft.mode)
			} else {
				err = os.Remove(path)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("restore rules %s: %w", path, err))
			}
		}
		return errors.Join(errs...)
	}
	for _, path := range paths {
		draft := d.files[path]
		if err := atomicWriteFile(path, draft.data, draft.mode); err != nil {
			return nil, errors.Join(fmt.Errorf("save rules %s: %w", path, err), rollback())
		}
		written = append(written, path)
	}
	return rollback, nil
}

func editRuleDraft(path string) {
	if tuiRuleDrafts == nil {
		tuiNote("Rules not changed", "open the settings page to edit rules")
		return
	}
	changed, err := tuiRuleDrafts.edit(path)
	if err != nil {
		tuiNote("Rules not changed", err.Error())
		return
	}
	if changed {
		tuiNote("Rule changes staged", "use Save to apply, or Discard to cancel")
	}
}

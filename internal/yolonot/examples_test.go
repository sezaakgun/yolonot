package yolonot

import (
	"path/filepath"
	"testing"
)

func TestExampleConfigsStayValid(t *testing.T) {
	files, _ := filepath.Glob("../../examples/*.json")
	if len(files) == 0 {
		t.Fatal("no example configs found")
	}
	for _, f := range files {
		cfg, err := readConfig(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

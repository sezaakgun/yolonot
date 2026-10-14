package yolonot

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func installHarnessSkill(harnessName, skillDir string) (string, error) {
	data := strings.ReplaceAll(string(embeddedSkillMD), "{{HARNESS}}", harnessName)
	path := filepath.Join(skillDir, "SKILL.md")
	if existing, err := os.ReadFile(path); err == nil && !strings.Contains(string(existing), "yolonot-managed-skill") {
		// Adopt only the byte-identical skill shipped in v1 before ownership
		// markers. Preserve it for recovery; customized user skills stay intact.
		if harnessName != "claude" || fmt.Sprintf("%x", sha256.Sum256(existing)) != "608645ce5669d29d0645a714e74ca96c14e8d270035f6c504ca9a078d02e28ba" {
			return "", fmt.Errorf("refusing to overwrite unmanaged skill: %s", path)
		}
		backup := path + ".pre-port.bak"
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			if err := atomicWriteFile(backup, existing, 0644); err != nil {
				return "", err
			}
		} else if err != nil {
			return "", err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := atomicWriteFile(path, []byte(data), 0644); err != nil {
		return "", err
	}
	return skillDir, nil
}

func uninstallHarnessSkill(skillDir string) error {
	path := filepath.Join(skillDir, "SKILL.md")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.Contains(string(data), "yolonot-managed-skill") {
		return fmt.Errorf("refusing to remove unmanaged skill: %s", path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	// Leave unrelated user files in the directory alone.
	_ = os.Remove(skillDir)
	return nil
}

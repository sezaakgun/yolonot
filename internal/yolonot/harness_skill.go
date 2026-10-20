package yolonot

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SHA-256 of every SKILL.md released without the ownership marker.
var shippedUnmarkedSkills = map[string]bool{
	"84ed0326ac2b58673ac9d7ccb9e278df25a9f1413ed6909b5226dd542a71cbd0": true, // v0.2.0
	"f7cae3e0b2f5593fbc38205938c649da298d8d6c6ebd5d17445745181a3e3bbf": true, // v0.3.0
	"40f43063aa7014e84d7bca05c809df12e99959bddc419e41d17d8f83be7b3fd7": true, // v0.3.1
	"81e7f4e9589c378f000620014d0ea50c544fd9821c51df6cb2973e848bfb0060": true, // v0.6.0
	"f4e7b34e92ab647ad0ead1e2b26f6e2b808f039c538b9d4c26f5778db8b829d8": true, // v0.7.0
	"3a8d675ad280ecfba297f9beb62bc57d187fbfc2a10574fd06d2072369cdd016": true, // v0.8.0
	"52ef1910c7bca0e728e710b080f50dd98a85e6c1d07868151b1178cfc66d9e32": true, // v0.9.0
	"0d22a9aa3642ac6f96ed8a06cbb943ef157e284bd72bb8513b86802bf83d3718": true, // v0.13.0
	"33c95b57c6bad734d51be7c53d305d234ba3055fd3c0cea4bfe2df8d9ecd131a": true, // v0.15.1
	"ec39da60daa50b2f8277100a776dee21ab3e8d1b359c4799c4044b5ad7ed1b4d": true, // v0.21.0
	"608645ce5669d29d0645a714e74ca96c14e8d270035f6c504ca9a078d02e28ba": true, // 5cbc7de
}

func installHarnessSkill(harnessName, skillDir string) (string, error) {
	data := strings.ReplaceAll(string(embeddedSkillMD), "{{HARNESS}}", harnessName)
	path := filepath.Join(skillDir, "SKILL.md")
	if existing, err := os.ReadFile(path); err == nil && !strings.Contains(string(existing), "yolonot-managed-skill") {
		// Adopt only a byte-identical skill shipped before ownership markers.
		// Preserve it for recovery; customized user skills stay intact.
		if harnessName != "claude" || !shippedUnmarkedSkills[fmt.Sprintf("%x", sha256.Sum256(existing))] {
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
	if !strings.Contains(string(data), "yolonot-managed-skill") && !shippedUnmarkedSkills[fmt.Sprintf("%x", sha256.Sum256(data))] {
		return fmt.Errorf("refusing to remove unmanaged skill: %s", path)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	// Leave unrelated user files in the directory alone.
	_ = os.Remove(skillDir)
	return nil
}

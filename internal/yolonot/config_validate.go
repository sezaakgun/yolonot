package yolonot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
)

type FailurePolicy struct {
	Unavailable   string `json:"unavailable,omitempty"`
	Parse         string `json:"parse,omitempty"`
	InvalidConfig string `json:"invalid_config,omitempty"`
	Oversize      string `json:"oversize,omitempty"`
	Timeout       string `json:"timeout,omitempty"`
}

type LearningConfig struct {
	Enabled       *bool `json:"enabled,omitempty"`        // absent preserves existing enabled behavior
	RetentionDays int   `json:"retention_days,omitempty"` // 0 = no expiry
	MaxEntries    int   `json:"max_entries,omitempty"`    // 0 = no cap
}

// Reading never rewrites a legacy config. Decode errors never leave a partial
// policy active; validation errors preserve the decoded failure policy only.
func readConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return Config{}, fmt.Errorf("config must be a JSON object")
	}
	var cfg Config
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("invalid config JSON: %w", err)
	}
	if err := d.Decode(new(interface{})); err != io.EOF {
		return Config{}, fmt.Errorf("config contains trailing JSON")
	}
	if err := uniqueJSONFields(data); err != nil {
		return Config{}, err
	}
	if err := canonicalConfigFields(data, reflect.TypeOf(cfg)); err != nil {
		return Config{}, err
	}
	cfg.normalize()
	if err := ValidateConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func uniqueJSONFields(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name := strings.ToLower(key.(string))
				if seen[name] {
					return fmt.Errorf("duplicate config field %q", name)
				}
				seen[name] = true
				if err := value(); err != nil {
					return err
				}
			}
		} else if delim == '[' {
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
		}
		_, err = d.Token()
		return err
	}
	return value()
}

func canonicalConfigFields(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	data := bytes.TrimSpace(raw)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		if data[0] != '{' {
			return nil
		} // legacy custom decoders accept strings
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return err
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = field.Type
			}
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("unknown or noncanonical config field %q", name)
			}
			if err := canonicalConfigFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return err
		}
		for _, value := range object {
			if err := canonicalConfigFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if data[0] != '[' {
			return nil
		} // legacy pre_check also accepts one string
		var list []json.RawMessage
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		for _, value := range list {
			if err := canonicalConfigFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateConfig(cfg Config) error {
	var problems []string
	add := func(format string, a ...interface{}) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if cfg.ConfigVersion < 0 || cfg.ConfigVersion > 1 {
		add("unsupported config_version %d", cfg.ConfigVersion)
	}
	for name, m := range cfg.Models {
		if err := ValidModelName(name); err != nil {
			add("%v", err)
		}
		if strings.TrimSpace(m.Model) == "" || strings.TrimSpace(m.URL) == "" {
			add("model %q requires url and model", name)
		} else if m.URL != "claude-cli" {
			if err := validateLLMURL(m.URL); err != nil {
				add("model %q has invalid URL", name)
			}
		}
		if m.Timeout < 0 || m.Timeout > 600 {
			add("model %q timeout must be 0..600 seconds", name)
		}
		if !validProtocol(m.Protocol) {
			add("model %q has unknown protocol %q", name, m.Protocol)
		}
		if modelProtocol(m) == "claude-cli" && m.URL != "claude-cli" {
			add("model %q: claude-cli protocol requires claude-cli URL", name)
		}
		if m.URL == "claude-cli" && m.Protocol != "" && m.Protocol != "claude-cli" {
			add("model %q: claude-cli URL requires claude-cli protocol", name)
		}
	}
	for _, spec := range cfg.Judges {
		if err := validateJudgeSpec(cfg, spec); err != nil {
			add("%v", err)
		}
	}
	if cfg.Escalation != nil {
		if cfg.Escalation.Model != "" {
			if _, ok := cfg.Models[cfg.Escalation.Model]; !ok {
				add("escalation refers to missing model %q", cfg.Escalation.Model)
			}
		}
		if cfg.Escalation.Unresolved != "" && cfg.Escalation.Unresolved != ActionAsk && cfg.Escalation.Unresolved != ActionDeny {
			add("escalation.unresolved must be ask or deny")
		}
	}
	profileKnown := func(name string) bool {
		_, custom := cfg.Policy.Profiles[name]
		return name == "" || IsBuiltinProfileName(name) || custom
	}
	if !profileKnown(cfg.Policy.Profile) {
		add("unknown policy profile %q", cfg.Policy.Profile)
	}
	for name, p := range cfg.Policy.Profiles {
		if err := ValidateCustomProfile(name, p); err != nil {
			add("%v", err)
		}
	}
	for name, hp := range cfg.Policy.Harness {
		if h := GetHarness(name); h == nil {
			add("unknown harness %q in policy", name)
		} else if h.Name() != name {
			add("harness %q in policy must be written as %q", name, h.Name())
		}
		if !profileKnown(hp.Profile) {
			add("harness %q has unknown profile %q", name, hp.Profile)
		}
		for tier, act := range hp.RiskMap {
			if !isValidRisk(tier) || (act != ActionAllow && act != ActionAsk && act != ActionDeny && act != ActionPassthrough) {
				add("invalid risk map cell %s.%s", name, tier)
			}
		}
	}
	for name, act := range map[string]string{"unavailable": cfg.Failure.Unavailable, "parse": cfg.Failure.Parse, "invalid_config": cfg.Failure.InvalidConfig, "oversize": cfg.Failure.Oversize, "timeout": cfg.Failure.Timeout} {
		if act != "" && act != ActionAsk && act != ActionDeny && act != ActionPassthrough {
			add("failure.%s must be ask, deny or passthrough", name)
		}
	}
	if cfg.HookTimeout < 0 || cfg.HookTimeout > 55 {
		add("hook_timeout must be 1..55 seconds, or 0 for default")
	}
	if cfg.Learning.RetentionDays < 0 || cfg.Learning.MaxEntries < 0 {
		add("learning retention_days and max_entries must be nonnegative")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid config: %s", strings.Join(problems, "; "))
	}
	return nil
}

func mustSaveConfig(cfg Config) {
	if err := ValidateConfig(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "yolonot:", err)
		os.Exit(2)
	}
	if err := SaveConfig(cfg); err != nil {
		os.Exit(1)
	}
}

func cmdConfigValidate(args []string) {
	path := configPath()
	if len(args) > 0 {
		path = args[0]
	}
	cfg, err := readConfig(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("Config valid: %s (%d models, %d judges)\n", path, len(cfg.Models), len(cfg.Judges))
}

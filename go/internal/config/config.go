// Package config loads the TOML config, mirroring config.py's schema/defaults.
package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type LLM struct {
	Provider      string  `toml:"provider" json:"provider"`
	Model         string  `toml:"model" json:"model"`
	Host          string  `toml:"host" json:"host"`
	APIKey        string  `toml:"api_key" json:"api_key"`
	Temperature   float64 `toml:"temperature" json:"temperature"`
	MaxTokens     int     `toml:"max_tokens" json:"max_tokens"`
	ContextWindow int     `toml:"context_window" json:"context_window"`
}

type History struct {
	Directory string `toml:"directory" json:"directory"`
	MaxFiles  int    `toml:"max_files" json:"max_files"`
}

type Models struct {
	Directory     string `toml:"directory" json:"directory"`
	Method        string `toml:"method" json:"method"` // statistical | baseline | lstm
	Sensitivity   string `toml:"sensitivity" json:"sensitivity"`
	HistoryWindow int    `toml:"history_window" json:"history_window"`
	// Adaptive baseline (method = "baseline").
	EWMAAlpha  float64 `toml:"ewma_alpha" json:"ewma_alpha"`
	Seasonal   bool    `toml:"seasonal" json:"seasonal"`
	MinUpdates int     `toml:"min_updates" json:"min_updates"`
	// LSTM-specific (method = "lstm").
	LSTMTimesteps int `toml:"lstm_timesteps" json:"lstm_timesteps"`
	MinSamples    int `toml:"min_samples_train" json:"min_samples_train"`
}

type Config struct {
	LLM     LLM     `toml:"llm" json:"llm"`
	History History `toml:"history" json:"history"`
	Models  Models  `toml:"models" json:"models"`
}

// Default mirrors DEFAULT_CONFIG in config.py.
func Default() Config {
	return Config{
		LLM: LLM{Temperature: 0.2, MaxTokens: 1024, ContextWindow: 4096},
		History: History{
			Directory: "/var/lib/sysdiag-analyzer/history",
			MaxFiles:  50,
		},
		Models: Models{
			Directory:     "/var/lib/sysdiag-analyzer/models",
			Method:        "statistical",
			Sensitivity:   "medium",
			HistoryWindow: 30,
			EWMAAlpha:     0.3,
			MinUpdates:    8,
			LSTMTimesteps: 5,
			MinSamples:    10,
		},
	}
}

// DefaultPaths mirrors DEFAULT_CONFIG_FILES (system then user; later overrides earlier).
func DefaultPaths() []string {
	paths := []string{"/etc/sysdiag-analyzer/config.toml"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config/sysdiag-analyzer/config.toml"))
	}
	return paths
}

// Load merges defaults with the override file (if given) or the default search paths.
func Load(override string) Config {
	cfg := Default()
	var files []string
	if override != "" {
		if _, err := os.Stat(override); err == nil {
			files = []string{override}
		} else {
			return cfg
		}
	} else {
		files = DefaultPaths()
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		_, _ = toml.DecodeFile(f, &cfg) // best-effort, like the Python loader
	}
	return cfg
}

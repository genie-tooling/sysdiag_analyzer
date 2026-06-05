// Package llm synthesizes the report via a local Ollama or any OpenAI-compatible
// endpoint. Uses plain net/http (no SDK dependency), mirroring llm_analyzer.py.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/config"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

func isClaudeCode(provider string) bool {
	switch provider {
	case "claude-code", "claude-cli", "claude":
		return true
	}
	return false
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// Analyze runs the configured provider over a prompt built from the report.
func Analyze(report *types.SystemReport, cfg config.LLM) *types.LLMAnalysisResult {
	res := &types.LLMAnalysisResult{ProviderUsed: cfg.Provider, ModelUsed: cfg.Model}
	if cfg.Provider == "" {
		res.Error = "LLM provider not configured ([llm].provider)."
		return res
	}
	if cfg.Model == "" && !isClaudeCode(cfg.Provider) {
		// claude-code may use the CLI's default model, so a model is optional there.
		res.Error = "LLM model not configured ([llm].model)."
		return res
	}
	prompt := BuildPrompt(report)
	temp := cfg.Temperature
	maxTok := cfg.MaxTokens
	if maxTok == 0 {
		maxTok = 1024
	}

	var synth string
	var pTok, cTok *int
	var err error
	switch {
	case cfg.Provider == "ollama":
		synth, pTok, cTok, err = generateOllama(cfg, prompt, temp, maxTok)
	case cfg.Provider == "openai" || cfg.Provider == "openai-compatible":
		synth, pTok, cTok, err = generateOpenAI(cfg, prompt, temp, maxTok)
	case isClaudeCode(cfg.Provider):
		var model string
		synth, model, pTok, cTok, err = generateClaudeCode(cfg, prompt)
		if model != "" {
			res.ModelUsed = model
		}
	default:
		res.Error = "unsupported LLM provider: " + cfg.Provider
		return res
	}
	if err != nil {
		res.Error = "LLM generation failed: " + err.Error()
		return res
	}
	res.Synthesis = synth
	res.PromptTokenCount = pTok
	res.CompletionTokenCount = cTok
	return res
}

func generateOllama(cfg config.LLM, prompt string, temp float64, maxTok int) (string, *int, *int, error) {
	host := cfg.Host
	if host == "" {
		host = "http://localhost:11434"
	}
	body, _ := json.Marshal(map[string]any{
		"model": cfg.Model, "prompt": prompt, "stream": false,
		"options": map[string]any{"temperature": temp, "num_predict": maxTok, "num_ctx": cfg.ContextWindow},
	})
	var out struct {
		Response        string `json:"response"`
		PromptEvalCount int    `json:"prompt_eval_count"`
		EvalCount       int    `json:"eval_count"`
	}
	if err := postJSON(strings.TrimRight(host, "/")+"/api/generate", nil, body, &out); err != nil {
		return "", nil, nil, err
	}
	if out.Response == "" {
		return "", nil, nil, fmt.Errorf("ollama returned no response")
	}
	return strings.TrimSpace(out.Response), &out.PromptEvalCount, &out.EvalCount, nil
}

func generateOpenAI(cfg config.LLM, prompt string, temp float64, maxTok int) (string, *int, *int, error) {
	base := cfg.Host
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	key := cfg.APIKey
	if key == "" {
		key = os.Getenv("OPENAI_API_KEY")
	}
	if key == "" {
		key = "not-needed" // keyless local servers (vLLM/llama.cpp/LocalAI)
	}
	body, _ := json.Marshal(map[string]any{
		"model":       cfg.Model,
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"temperature": temp,
		"max_tokens":  maxTok,
	})
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	hdr := map[string]string{"Authorization": "Bearer " + key}
	if err := postJSON(strings.TrimRight(base, "/")+"/chat/completions", hdr, body, &out); err != nil {
		return "", nil, nil, err
	}
	if len(out.Choices) == 0 || out.Choices[0].Message.Content == "" {
		return "", nil, nil, fmt.Errorf("openai-compatible endpoint returned no content")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), &out.Usage.PromptTokens, &out.Usage.CompletionTokens, nil
}

// generateClaudeCode runs the local Claude Code CLI headlessly (`claude -p
// --output-format json`), feeding the prompt on stdin. It uses the user's
// existing Claude Code auth, so no API key is needed in the config. The CLI
// binary path can be overridden via [llm].host; the model via [llm].model.
func generateClaudeCode(cfg config.LLM, prompt string) (synth, model string, pTok, cTok *int, err error) {
	bin := cfg.Host
	if bin == "" {
		bin = "claude"
	}
	args := []string{"-p", "--output-format", "json"}
	if cfg.Model != "" {
		args = append(args, "--model", cfg.Model)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(prompt)
	out, runErr := cmd.Output()
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return "", "", nil, nil, fmt.Errorf("claude CLI: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return "", "", nil, nil, fmt.Errorf("claude CLI (%s): %w", bin, runErr)
	}
	var parsed struct {
		Result  string `json:"result"`
		IsError bool   `json:"is_error"`
		Model   string `json:"model"`
		Usage   struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if jsonErr := json.Unmarshal(out, &parsed); jsonErr != nil {
		// Tolerate a plain-text response (e.g. a future --output-format default).
		if s := strings.TrimSpace(string(out)); s != "" {
			return s, "", nil, nil, nil
		}
		return "", "", nil, nil, fmt.Errorf("claude CLI returned no parseable output")
	}
	if parsed.IsError {
		return "", "", nil, nil, fmt.Errorf("claude CLI error: %s", strings.TrimSpace(parsed.Result))
	}
	if strings.TrimSpace(parsed.Result) == "" {
		return "", "", nil, nil, fmt.Errorf("claude CLI returned an empty result")
	}
	return strings.TrimSpace(parsed.Result), parsed.Model, &parsed.Usage.InputTokens, &parsed.Usage.OutputTokens, nil
}

func postJSON(url string, headers map[string]string, body []byte, out any) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

// BuildPrompt produces a concise, data-grounded prompt from the report.
func BuildPrompt(r *types.SystemReport) string {
	var b strings.Builder
	b.WriteString("You are a System Diagnostics Analyzer AI. Analyze ONLY the data below and " +
		"produce a concise Markdown summary: overall health, issue breakdown with likely causes, " +
		"and 1-3 actionable recommendations per issue. Do not speculate beyond the data.\n\n")
	fmt.Fprintf(&b, "## System\n- Host: %s\n- Boot: %s\n", r.Hostname, r.BootID)
	if r.BootAnalysis != nil && r.BootAnalysis.Times != nil && r.BootAnalysis.Times.Total != "" {
		fmt.Fprintf(&b, "- Total boot time: %s\n", r.BootAnalysis.Times.Total)
	}
	if h := r.HealthAnalysis; h != nil {
		fmt.Fprintf(&b, "\n## Health\n- %d units, %d failed, %d flapping\n", h.AllUnitsCount, len(h.FailedUnits), len(h.FlappingUnits))
		for _, u := range h.FailedUnits {
			fmt.Fprintf(&b, "- FAILED: %s\n", u.Name)
		}
	}
	if ra := r.ResourceAnalysis; ra != nil && ra.SystemUsage != nil {
		su := ra.SystemUsage
		if su.MemPercent != nil {
			fmt.Fprintf(&b, "\n## Resources\n- Memory: %.1f%%\n", *su.MemPercent)
		}
		if su.SwapPercent != nil {
			fmt.Fprintf(&b, "- Swap: %.1f%%\n", *su.SwapPercent)
		}
		for i, u := range ra.TopMemoryUnits {
			if i >= 3 {
				break
			}
			fmt.Fprintf(&b, "- Top mem: %s\n", u.Name)
		}
	}
	if l := r.LogAnalysis; l != nil && len(l.DetectedPatterns) > 0 {
		b.WriteString("\n## Log patterns\n")
		for _, p := range l.DetectedPatterns {
			fmt.Fprintf(&b, "- %s %s ×%d\n", p.PatternType, p.PatternKey, p.Count)
		}
	}
	if ml := r.MLAnalysis; ml != nil && len(ml.AnomaliesDetected) > 0 {
		b.WriteString("\n## Anomalies\n")
		for _, a := range ml.AnomaliesDetected {
			fmt.Fprintf(&b, "- %s (score %.1f)\n", a.UnitName, a.Score)
		}
	}
	if lk := r.MemoryLeakAnalysis; lk != nil && len(lk.SuspectedLeaks) > 0 {
		b.WriteString("\n## Suspected memory leaks\n")
		for _, s := range lk.SuspectedLeaks {
			fmt.Fprintf(&b, "- %s (%.0f bytes/hour)\n", s.UnitName, s.SlopeBytesPerHour)
		}
	}
	return b.String()
}

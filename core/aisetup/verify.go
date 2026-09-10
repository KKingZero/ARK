package aisetup

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/llm"
)

type verifyLine struct {
	OK   bool
	Text string
}

type verifyMsg struct {
	Lines []verifyLine
}

func runVerify(provider, model, baseURL, apiKey string) verifyMsg {
	cfg, err := llm.Load(llm.DefaultConfigPath)
	if err != nil {
		cfg = llm.Config{
			Provider: provider,
			Model:    model,
			BaseURL:  baseURL,
			APIKey:   apiKey,
		}
	}
	var lines []verifyLine

	if provider == string(llm.ProviderOllama) {
		models, err := llm.ProbeOllama(cfg.BaseURL, cfg.APIKey)
		if err != nil {
			lines = append(lines, verifyLine{false, "Ollama reachable — " + err.Error()})
		} else {
			lines = append(lines, verifyLine{true, "Ollama reachable"})
			found := false
			for _, n := range models {
				if n == model || n == model+":latest" || strings.Split(n, ":")[0] == strings.Split(model, ":")[0] {
					found = true
					break
				}
			}
			if found || model == "" {
				lines = append(lines, verifyLine{true, model + " available"})
			} else {
				lines = append(lines, verifyLine{false, model + " not in Ollama list"})
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	d, err := llm.Ping(ctx, cfg)
	if err != nil {
		lines = append(lines, verifyLine{false, "Inference test failed — " + err.Error()})
	} else {
		ms := d.Round(time.Millisecond)
		lines = append(lines, verifyLine{true, fmt.Sprintf("Inference test passed — %s", ms)})
	}
	return verifyMsg{Lines: lines}
}

func locality(provider, baseURL string) string {
	if provider != string(llm.ProviderOllama) {
		return "Cloud"
	}
	switch llm.DetectOllamaMode(baseURL) {
	case llm.OllamaModeLocal:
		return "Local"
	case llm.OllamaModeRemote:
		return "Remote"
	default:
		return "Cloud"
	}
}

func wizardPhase(s step) (int, string) {
	switch s {
	case stepProvider:
		return 1, "Provider"
	case stepOllamaMode, stepOllamaHost, stepAuth, stepKey:
		return 2, "Connection"
	case stepModel, stepCustomModel:
		return 3, "Model"
	default:
		return 4, "Verify"
	}
}

package llm

import (
	"errors"
	"strings"
	"testing"
)

func TestBillingWarningOpenAIAndAnthropic(t *testing.T) {
	o := BillingWarning("openai")
	if o == "" || !strings.Contains(o, "ChatGPT Plus") || !strings.Contains(o, "Codex") {
		t.Fatalf("openai warning %q", o)
	}
	a := BillingWarning("anthropic")
	if a == "" || !strings.Contains(a, "Claude Pro") || !strings.Contains(a, "Claude Code") {
		t.Fatalf("anthropic warning %q", a)
	}
	if BillingWarning("grok") != "" {
		t.Fatal("grok should have no plus-vs-api warning")
	}
}

func TestAPIErrorHintQuota(t *testing.T) {
	err := errors.New("openai chat (gpt-4o): You exceeded your current quota, please check your plan and billing details (insufficient_quota)")
	h := APIErrorHint("openai", err)
	if h == "" || !strings.Contains(h, "Codex") {
		t.Fatalf("hint %q", h)
	}
}

func TestAPIErrorHintBalanceParaphrase(t *testing.T) {
	err := errors.New("openai chat (gpt-4o): insufficient balance")
	if !LooksLikeQuotaOrBillingError(err) {
		t.Fatal("expected quota match for insufficient balance")
	}
	if APIErrorHint("openai", err) == "" {
		t.Fatal("expected openai hint")
	}
}

func TestAPIErrorHintAnthropicCredits(t *testing.T) {
	err := errors.New("anthropic chat: Your credit balance is too low to access the Anthropic API")
	h := APIErrorHint("anthropic", err)
	if h == "" || !strings.Contains(h, "console.anthropic.com") {
		t.Fatalf("hint %q", h)
	}
}

func TestAPIErrorHintIgnoresNetwork(t *testing.T) {
	err := errors.New("openai chat: connection refused")
	if APIErrorHint("openai", err) != "" {
		t.Fatal("network errors should not get a billing hint")
	}
}

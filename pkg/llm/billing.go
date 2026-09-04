package llm

import (
	"strings"
)

// BillingWarning explains that hosted OpenAI/Anthropic in ARK are prepaid
// Platform/API keys, not ChatGPT Plus/Codex or Claude Pro/Claude Code.
func BillingWarning(provider string) string {
	switch ProviderID(provider) {
	case ProviderOpenAI:
		return "OpenAI here is the Platform API (api.openai.com), not ChatGPT Plus or Codex. A $20 Codex plan can still show remaining usage and fail with insufficient quota — load API credits at platform.openai.com, or pick another provider."
	case ProviderAnthropic:
		return "Anthropic here is the API (console.anthropic.com), not Claude Pro or Claude Code. Subscription usage does not pay API calls — add credits at console.anthropic.com, or pick another provider."
	default:
		return ""
	}
}

// APIErrorHint returns an extra operator hint for quota/auth failures.
func APIErrorHint(provider string, err error) string {
	if err == nil {
		return ""
	}
	if !LooksLikeQuotaOrBillingError(err) && !LooksLikeAuthError(err) {
		return ""
	}
	return BillingWarning(provider)
}

// LooksLikeQuotaOrBillingError reports vendor credit/quota failures
// (including testers paraphrasing OpenAI insufficient_quota as "insufficient balance").
func LooksLikeQuotaOrBillingError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	needles := []string{
		"insufficient_quota",
		"insufficient quota",
		"insufficient balance",
		"insufficient credit",
		"credit balance",
		"exceeded your current quota",
		"quota exceeded",
		"billing_not_active",
		"billing hard limit",
		"too low to access",
		"spend limit",
		"you have insufficient",
	}
	return containsAny(s, needles)
}

// LooksLikeAuthError reports invalid-key / unauthorized failures.
func LooksLikeAuthError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	needles := []string{
		"invalid api key",
		"incorrect api key",
		"invalid_api_key",
		"invalid x-api-key",
		"unauthorized",
		"status code: 401",
		"statuscode: 401",
		"401 unauthorized",
	}
	return containsAny(s, needles)
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

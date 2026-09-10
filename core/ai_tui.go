package core

import (
	"fmt"
	"os"

	"github.com/KKingZero/ARK/core/aitui"
	"github.com/KKingZero/ARK/pkg/agent"
	"github.com/KKingZero/ARK/pkg/llm"
)

func (c *Console) runAITUI(initialMsg string) {
	if c.mode == OutputJSON {
		if initialMsg != "" {
			c.runAI(initialMsg)
		} else {
			emitError(c.mode, "ai", "JSON mode: use ai \"<objective>\" for one-shot chat")
		}
		return
	}

	llmCfg, err := llm.Load(llm.DefaultConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ai: %v\n", err)
		return
	}
	if llmCfg.Provider == string(llm.ProviderOllama) {
		if resolved, err := llm.ResolveOllamaModel(llmCfg); err == nil {
			llmCfg = resolved
		}
	}

	var agentCfg *agent.Config
	if ac, ok := agentAvailable(llmCfg); ok {
		agentCfg = ac
	}

	sessions := 0
	if agentCfg != nil {
		sessions = c.sessionCount()
	}
	mode, err := aitui.Run(aitui.Options{
		LLMCfg:     llmCfg,
		AgentCfg:   agentCfg,
		InitialMsg: initialMsg,
		Sessions:   sessions,
		OnServe: func() (*agent.Config, int, error) {
			if err := c.ensureServe(); err != nil {
				return nil, 0, err
			}
			fresh, err := llm.Load(llm.DefaultConfigPath)
			if err != nil {
				fresh = llmCfg
			}
			ac, ok := agentAvailable(fresh)
			if !ok {
				return nil, 0, fmt.Errorf("teamserver is up; Auto still needs operator + approver certs (~/.ark/certs/)")
			}
			return ac, c.sessionCount(), nil
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ai tui: %v\n", err)
		return
	}
	if mode == aitui.QuitAll {
		c.running = false
	}
}

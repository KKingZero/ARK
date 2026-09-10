package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/arkcli"
	"github.com/KKingZero/ARK/pkg/llm"
	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/server"
)

// RuntimeStatus is the snapshot printed by `status` and `serve`.
type RuntimeStatus struct {
	Teamserver bool
	Operator   bool
	GRPCAddr   string
	Listeners  []string
	Sessions   int
	AIProvider string
	AIModel    string
	Engagement string
	Approval   string
}

func (c *Console) snapshot() RuntimeStatus {
	cfg, err := server.LoadConfig(server.ConfigPath())
	if err != nil {
		cfg = server.DefaultConfig()
	}
	st := RuntimeStatus{
		GRPCAddr:   cfg.GRPCAddr,
		Engagement: strings.TrimSpace(c.workspace),
		Approval:   "required",
	}
	if st.Engagement == "" {
		st.Engagement = "default"
	}
	for _, l := range cfg.Listeners {
		proto := strings.ToUpper(l.Protocol)
		if proto == "" {
			proto = "HTTPS"
		}
		st.Listeners = append(st.Listeners, fmt.Sprintf("%s :%d", proto, l.Port))
	}

	st.Teamserver = arkcli.GRPCReachable(cfg.GRPCAddr)
	c.online = st.Teamserver

	if llmCfg, err := llm.Load(llm.DefaultConfigPath); err == nil {
		st.AIProvider = llmCfg.Provider
		st.AIModel = llmCfg.Model
	}

	if !st.Teamserver {
		return st
	}

	client, _, err := c.team.connect()
	if err != nil {
		return st
	}
	st.Operator = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if resp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{}); err == nil {
		st.Sessions = len(resp.Sessions)
	}
	if resp, err := client.ListListeners(ctx, &pb.ListListenersRequest{}); err == nil && len(resp.Listeners) > 0 {
		st.Listeners = st.Listeners[:0]
		for _, l := range resp.Listeners {
			st.Listeners = append(st.Listeners, formatListener(l))
		}
	}
	return st
}

func formatListener(l *pb.ListenerStatus) string {
	if l == nil {
		return ""
	}
	proto := strings.TrimPrefix(l.Protocol.String(), "LISTENER_")
	if proto == "" {
		proto = "HTTPS"
	}
	addr := strings.TrimSpace(l.Address)
	if addr == "" {
		return proto
	}
	// Address is host:port; show :port when host is wildcard.
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return proto + " " + addr[i:]
	}
	return proto + " " + addr
}

func formatStatus(s RuntimeStatus) string {
	var b strings.Builder
	b.WriteString("\nARK C2\n")
	b.WriteString(fmt.Sprintf("Teamserver    %s\n", mark(s.Teamserver, "running", "stopped")))
	b.WriteString(fmt.Sprintf("Operator      %s\n", mark(s.Operator, "connected", "offline")))
	b.WriteString(fmt.Sprintf("Listener      %s\n", firstOr(s.Listeners, "—")))
	b.WriteString(fmt.Sprintf("Sessions      %d active\n", s.Sessions))
	ai := "—"
	if s.AIProvider != "" {
		ai = displayProvider(s.AIProvider)
		if s.AIModel != "" {
			ai += " / " + s.AIModel
		}
	}
	b.WriteString(fmt.Sprintf("AI            %s\n", ai))
	b.WriteString(fmt.Sprintf("Engagement    %s\n", s.Engagement))
	b.WriteString(fmt.Sprintf("Approval      %s\n", s.Approval))
	return b.String()
}

func formatServeOK(s RuntimeStatus) string {
	var b strings.Builder
	b.WriteString("✓ Teamserver running\n")
	b.WriteString(fmt.Sprintf("  Operator API   %s\n", s.GRPCAddr))
	b.WriteString(fmt.Sprintf("  HTTPS listener %s\n", listenerPort(s)))
	b.WriteString(fmt.Sprintf("  Engagement     %s\n", s.Engagement))
	return b.String()
}

func listenerPort(s RuntimeStatus) string {
	if len(s.Listeners) == 0 {
		return "—"
	}
	// Prefer a :port fragment.
	for _, l := range s.Listeners {
		if i := strings.LastIndex(l, ":"); i >= 0 {
			return l[i:]
		}
	}
	return s.Listeners[0]
}

func mark(ok bool, on, off string) string {
	if ok {
		return "● " + on
	}
	return "○ " + off
}

func firstOr(items []string, fallback string) string {
	if len(items) == 0 || items[0] == "" {
		return fallback
	}
	return items[0]
}

func displayProvider(id string) string {
	switch strings.ToLower(id) {
	case "ollama":
		return "Ollama"
	case "openai":
		return "OpenAI"
	case "anthropic":
		return "Anthropic"
	case "grok":
		return "Grok"
	case "gemini":
		return "Gemini"
	case "kimi":
		return "Kimi"
	case "bedrock":
		return "Bedrock"
	default:
		if id == "" {
			return "—"
		}
		return strings.ToUpper(id[:1]) + id[1:]
	}
}

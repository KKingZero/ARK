package core

import (
	"fmt"

	"github.com/KKingZero/ARK/pkg/arkcli"
)

func (c *Console) cmdServe() {
	if err := c.ensureServe(); err != nil {
		emitError(c.mode, "serve", err.Error())
		return
	}
	st := c.snapshot()
	emit(c.mode, Response{
		Status:  "ok",
		Command: "serve",
		Message: formatServeOK(st),
		Data: map[string]interface{}{
			"grpc":       st.GRPCAddr,
			"listeners":  st.Listeners,
			"engagement": st.Engagement,
			"sessions":   st.Sessions,
		},
	})
}

func (c *Console) ensureServe() error {
	h, _, err := arkcli.EnsureTeamserver()
	if err != nil {
		return err
	}
	if h != nil {
		if c.ownedTS != nil && c.ownedTS != h {
			c.ownedTS.Stop()
		}
		c.ownedTS = h
	}
	c.online = true
	c.team.Close()
	return nil
}

func (c *Console) cmdStatus() {
	st := c.snapshot()
	emit(c.mode, Response{
		Status:  "ok",
		Command: "status",
		Message: formatStatus(st),
		Data: map[string]interface{}{
			"teamserver": st.Teamserver,
			"operator":   st.Operator,
			"grpc":       st.GRPCAddr,
			"listeners":  st.Listeners,
			"sessions":   st.Sessions,
			"ai":         st.AIProvider,
			"model":      st.AIModel,
			"engagement": st.Engagement,
		},
	})
}

func (c *Console) stopOwnedTeamserver() {
	if c.ownedTS != nil {
		c.ownedTS.Stop()
		c.ownedTS = nil
	}
	c.team.Close()
}

func (c *Console) sessionCount() int {
	return c.snapshot().Sessions
}

func (c *Console) cmdEngagements(args []string) {
	if len(args) == 0 {
		name := c.workspace
		if name == "" {
			name = "(none)"
		}
		emit(c.mode, Response{
			Status:  "ok",
			Command: "engagements",
			Message: fmt.Sprintf("> Engagement: %s", name),
			Data: map[string]string{
				"action":     "show",
				"engagement": c.workspace,
			},
		})
		return
	}
	switch args[0] {
	case "new":
		if len(args) < 2 {
			emitError(c.mode, "engagements", "Usage: engagements new <name>")
			return
		}
		c.workspace = args[1]
		emit(c.mode, Response{
			Status:  "ok",
			Command: "engagements",
			Message: fmt.Sprintf("> Engagement: %s", c.workspace),
			Data: map[string]string{
				"action":     "created",
				"engagement": c.workspace,
			},
		})
	case "list", "show":
		c.cmdEngagements(nil)
	default:
		emitError(c.mode, "engagements", fmt.Sprintf("Unknown engagements action: %s (new|list)", args[0]))
	}
}

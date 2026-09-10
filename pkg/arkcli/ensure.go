package arkcli

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/KKingZero/ARK/server"
)

// TeamserverHandle is a teamserver this process started and therefore owns.
type TeamserverHandle struct {
	TS     *server.Teamserver
	Config *server.Config
}

func (h *TeamserverHandle) Stop() {
	if h != nil && h.TS != nil {
		h.TS.Stop()
	}
}

// EnsureTeamserver starts the teamserver in-process if nothing is listening
// on the configured gRPC address. If a teamserver is already reachable, it
// returns (nil, cfg, nil) and the caller must not stop it.
//
// Stdlib log output is silenced during boot so the ARK shell can print a
// human status block instead of raw daemon lines.
func EnsureTeamserver() (*TeamserverHandle, *server.Config, error) {
	configPath := server.ConfigPath()
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		cfg = server.DefaultConfig()
	}
	if err := cfg.EnsureDirs(); err != nil {
		return nil, cfg, fmt.Errorf("create data dirs: %w", err)
	}

	if GRPCReachable(cfg.GRPCAddr) {
		return nil, cfg, nil
	}

	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)

	ts, err := server.NewTeamserver(cfg)
	if err != nil {
		return nil, cfg, fmt.Errorf("init teamserver: %w", err)
	}
	if _, _, _, err := EnsureOperatorCerts(cfg.DataDir); err != nil {
		return nil, cfg, err
	}
	// Approver seat lets AI Auto approve in-TUI. Best-effort: operator-only
	// still starts the C2; Auto will explain if the seat is missing.
	_, _ = EnsureSeatCerts(cfg.DataDir)
	if err := cfg.Save(configPath); err != nil {
		log.SetOutput(prev)
		log.Printf("[ark] warning: save config: %v", err)
		log.SetOutput(io.Discard)
	}
	if err := ts.Start(); err != nil {
		return nil, cfg, fmt.Errorf("start teamserver: %w", err)
	}
	for i := 0; i < 20 && !GRPCReachable(cfg.GRPCAddr); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if !GRPCReachable(cfg.GRPCAddr) {
		ts.Stop()
		return nil, cfg, fmt.Errorf("teamserver started but gRPC %s never became reachable", cfg.GRPCAddr)
	}
	return &TeamserverHandle{TS: ts, Config: cfg}, cfg, nil
}

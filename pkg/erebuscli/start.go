package erebuscli

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/operatorcli"
	"github.com/KKingZero/erebus-exploit-framwork/server"
)

// serveHooks lets tests drive REPL exit and shutdown without a TTY or signals.
type serveHooks struct {
	runREPL  func(operatorcli.Options) error
	waitStop func()
}

func defaultServeHooks() serveHooks {
	return serveHooks{
		runREPL:  operatorcli.RunREPL,
		waitStop: waitOSSignals,
	}
}

func waitOSSignals() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

// Start boots the teamserver (if needed) and launches the operator REPL.
// REPL / stdin EOF does not stop C2. Listeners die only on SIGINT/SIGTERM.
func Start() error {
	configPath := server.ConfigPath()
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		log.Printf("[erebus] no config at %s, using defaults", configPath)
		cfg = server.DefaultConfig()
	}
	return runServe(cfg, configPath, defaultServeHooks())
}

func runServe(cfg *server.Config, configPath string, h serveHooks) error {
	if err := cfg.EnsureDirs(); err != nil {
		return fmt.Errorf("create data dirs: %w", err)
	}
	if h.runREPL == nil {
		h.runREPL = operatorcli.RunREPL
	}
	if h.waitStop == nil {
		h.waitStop = waitOSSignals
	}

	var ts *server.Teamserver
	startedHere := false
	if !GRPCReachable(cfg.GRPCAddr) {
		var err error
		ts, err = server.NewTeamserver(cfg)
		if err != nil {
			return fmt.Errorf("init teamserver: %v", err)
		}
		if _, _, _, err := EnsureOperatorCerts(cfg.DataDir); err != nil {
			return err
		}
		// Persist after NewTeamserver so generated master_key is saved.
		if err := cfg.Save(configPath); err != nil {
			log.Printf("[erebus] warning: save config: %v", err)
		}
		if err := ts.Start(); err != nil {
			return fmt.Errorf("start teamserver: %w", err)
		}
		log.Printf("[erebus] teamserver started (gRPC=%s)", cfg.GRPCAddr)
		startedHere = true

		for i := 0; i < 20 && !GRPCReachable(cfg.GRPCAddr); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	} else {
		log.Printf("[erebus] teamserver already running at %s", cfg.GRPCAddr)
		if err := cfg.Save(configPath); err != nil {
			log.Printf("[erebus] warning: save config: %v", err)
		}
	}

	cert, key, ca, err := EnsureOperatorCerts(cfg.DataDir)
	if err != nil {
		log.Printf("[erebus] operator certs: %v (teamserver stays up)", err)
		if startedHere {
			h.waitStop()
			ts.Stop()
		}
		return err
	}

	fmt.Fprintf(os.Stderr, "[erebus] connecting operator to %s\n", cfg.GRPCAddr)
	fmt.Fprintf(os.Stderr, "[erebus] note: operator console EOF does not stop C2; SIGINT/SIGTERM to stop (or use `erebus teamserver` for daemon-only)\n")
	replErr := h.runREPL(operatorcli.Options{
		Server:   cfg.GRPCAddr,
		CertFile: cert,
		KeyFile:  key,
		CAFile:   ca,
	})
	if replErr != nil {
		log.Printf("[erebus] operator console ended: %v (teamserver stays up)", replErr)
	} else {
		log.Printf("[erebus] operator console closed; teamserver still running (SIGINT/SIGTERM to stop)")
	}

	if startedHere {
		h.waitStop()
		ts.Stop()
	}
	return replErr
}

// RunTeamserver runs the teamserver in the foreground (blocks until signal).
func RunTeamserver(configPath string, passphrase string) error {
	var cfg *server.Config
	var err error
	if passphrase != "" {
		cfg, err = server.LoadEncryptedConfig(configPath, passphrase)
		if err != nil {
			cfg, err = server.LoadConfig(configPath)
		}
	} else {
		cfg, err = server.LoadConfig(configPath)
	}
	if err != nil {
		log.Printf("[erebus] no config at %s, using defaults", configPath)
		cfg = server.DefaultConfig()
	}
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}

	ts, err := server.NewTeamserver(cfg)
	if err != nil {
		return err
	}
	if _, _, _, err := EnsureOperatorCerts(cfg.DataDir); err != nil {
		return err
	}
	// Persist after NewTeamserver so generated master_key is saved.
	if passphrase != "" {
		if err := cfg.SaveEncrypted(configPath, passphrase); err != nil {
			log.Printf("[erebus] warning: save encrypted config: %v", err)
		}
	} else if err := cfg.Save(configPath); err != nil {
		log.Printf("[erebus] warning: save config: %v", err)
	}
	if err := ts.Start(); err != nil {
		return err
	}

	log.Println("[erebus] teamserver running. Press Ctrl+C to stop.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ts.Stop()
	return nil
}

// DataDir returns the default erebus data directory.
func DataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".erebus")
}

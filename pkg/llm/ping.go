package llm

import (
	"context"
	"time"
)

// Ping runs a tiny chat completion to prove the provider/model can infer.
func Ping(ctx context.Context, cfg Config) (time.Duration, error) {
	client := NewClient(cfg)
	start := time.Now()
	_, err := client.Chat(ctx, "", "Reply with the single word: pong")
	return time.Since(start), err
}

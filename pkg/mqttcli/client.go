// Package mqttcli provides operator-local MQTT subscribe/publish helpers
// for authorized lab engagements (e.g. HTB Ghostlink healthcheck abuse).
package mqttcli

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Options configures an MQTT client connection.
type Options struct {
	Host     string
	Port     int
	ClientID string
	Username string
	Password string
}

func (o Options) brokerURL() string {
	port := o.Port
	if port == 0 {
		port = 1883
	}
	return fmt.Sprintf("tcp://%s:%d", o.Host, port)
}

func (o Options) clientID() string {
	if o.ClientID != "" {
		return o.ClientID
	}
	return fmt.Sprintf("erebus-%d", time.Now().UnixNano()%1_000_000_000)
}

func newClient(o Options) (mqtt.Client, error) {
	if o.Host == "" {
		return nil, fmt.Errorf("mqtt: host is required")
	}
	opts := mqtt.NewClientOptions()
	opts.AddBroker(o.brokerURL())
	opts.SetClientID(o.clientID())
	opts.SetConnectTimeout(10 * time.Second)
	opts.SetAutoReconnect(false)
	if o.Username != "" {
		opts.SetUsername(o.Username)
		opts.SetPassword(o.Password)
	}
	c := mqtt.NewClient(opts)
	tok := c.Connect()
	if !tok.WaitTimeout(15 * time.Second) {
		return nil, fmt.Errorf("mqtt: connect timeout to %s", o.brokerURL())
	}
	if err := tok.Error(); err != nil {
		return nil, fmt.Errorf("mqtt: connect %s: %w", o.brokerURL(), err)
	}
	return c, nil
}

// Message is a received MQTT message.
type Message struct {
	Topic   string
	Payload []byte
}

// Subscribe listens on topic for duration, writing lines to w (default stdout).
func Subscribe(o Options, topic string, duration time.Duration, w io.Writer) error {
	if topic == "" {
		topic = "#"
	}
	if duration <= 0 {
		duration = 20 * time.Second
	}
	if w == nil {
		w = os.Stdout
	}
	c, err := newClient(o)
	if err != nil {
		return err
	}
	defer c.Disconnect(250)

	var count atomic.Int64
	tok := c.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) {
		count.Add(1)
		fmt.Fprintf(w, "%s | %s\n", msg.Topic(), string(msg.Payload()))
	})
	if !tok.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("mqtt: subscribe timeout")
	}
	if err := tok.Error(); err != nil {
		return fmt.Errorf("mqtt: subscribe: %w", err)
	}
	fmt.Fprintf(w, "[mqtt] subscribed %s on %s for %s\n", topic, o.brokerURL(), duration)
	time.Sleep(duration)
	fmt.Fprintf(w, "[mqtt] done (%d messages)\n", count.Load())
	return nil
}

// Publish sends a payload to topic with optional retain and QoS 0/1.
func Publish(o Options, topic string, payload []byte, retain bool, qos byte) error {
	if topic == "" {
		return fmt.Errorf("mqtt: topic is required")
	}
	if qos > 1 {
		return fmt.Errorf("mqtt: qos must be 0 or 1")
	}
	c, err := newClient(o)
	if err != nil {
		return err
	}
	defer c.Disconnect(250)

	tok := c.Publish(topic, qos, retain, payload)
	if !tok.WaitTimeout(15 * time.Second) {
		return fmt.Errorf("mqtt: publish timeout")
	}
	if err := tok.Error(); err != nil {
		return fmt.Errorf("mqtt: publish: %w", err)
	}
	return nil
}

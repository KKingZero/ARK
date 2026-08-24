package netproxy

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProxyEnvPrecedence(t *testing.T) {
	t.Setenv("EREBUS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	if ProxyEnv() != "" {
		t.Fatal("empty")
	}
	t.Setenv("all_proxy", "socks5://127.0.0.1:1")
	if ProxyEnv() != "socks5://127.0.0.1:1" {
		t.Fatalf("all_proxy: %q", ProxyEnv())
	}
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:2")
	if ProxyEnv() != "socks5://127.0.0.1:2" {
		t.Fatalf("ALL_PROXY should win: %q", ProxyEnv())
	}
	t.Setenv("EREBUS_PROXY", "socks5://127.0.0.1:3")
	if ProxyEnv() != "socks5://127.0.0.1:3" {
		t.Fatalf("EREBUS_PROXY should win: %q", ProxyEnv())
	}
}

func TestSkipProxyLoopback(t *testing.T) {
	t.Setenv("EREBUS_PROXY_LOCAL", "")
	if !SkipProxy("127.0.0.1:389") || !SkipProxy("localhost:445") || !SkipProxy("[::1]:636") {
		t.Fatal("loopback should skip")
	}
	if SkipProxy("10.129.1.2:389") {
		t.Fatal("DC should not skip")
	}
	t.Setenv("EREBUS_PROXY_LOCAL", "1")
	if SkipProxy("127.0.0.1:389") {
		t.Fatal("EREBUS_PROXY_LOCAL=1 must not skip")
	}
}

func TestDialTimeoutDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, c)
		c.Close()
	}()
	t.Setenv("EREBUS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	c, err := DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-done
}

func TestSOCKSProxyIgnoresHTTP(t *testing.T) {
	t.Setenv("EREBUS_PROXY", "http://127.0.0.1:8080")
	if SOCKSProxy() != "" {
		t.Fatal("http proxy must not be used")
	}
	t.Setenv("EREBUS_PROXY", "socks5://127.0.0.1:1080")
	if SOCKSProxy() != "socks5://127.0.0.1:1080" {
		t.Fatalf("got %q", SOCKSProxy())
	}
}

func TestDialTimeoutIgnoresHTTPProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}()
	t.Setenv("EREBUS_PROXY", "http://127.0.0.1:1")
	t.Setenv("EREBUS_PROXY_LOCAL", "1")
	c, err := DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("http ALL_PROXY must dial direct: %v", err)
	}
	c.Close()
	<-done
}

func TestDialTimeoutDeadSOCKS(t *testing.T) {
	t.Setenv("EREBUS_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("EREBUS_PROXY_LOCAL", "1")
	_, err := DialTimeout("tcp", "10.129.0.1:389", 400*time.Millisecond)
	if err == nil {
		t.Fatal("expected proxy dial fail")
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Fatalf("error should name proxy: %v", err)
	}
}

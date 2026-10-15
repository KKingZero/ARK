package builder

import "testing"

func TestNormalizeBuildRequestDefaults(t *testing.T) {
	req := &BuildRequest{}
	if err := NormalizeBuildRequest(req); err != nil {
		t.Fatal(err)
	}
	if req.Language != DefaultLanguage || req.OS != DefaultOS || req.Arch != DefaultArch ||
		req.Format != DefaultFormat || req.Transport != DefaultTransport ||
		req.SleepMs != DefaultSleepMs || req.JitterPct != 0 {
		t.Fatalf("defaults not applied: %+v", req)
	}
	if len(req.Callbacks) != 1 || req.Callbacks[0] != DefaultCallback {
		t.Fatalf("callbacks=%v", req.Callbacks)
	}
}

func TestNormalizeBuildRequestPreservesZeroJitter(t *testing.T) {
	req := &BuildRequest{JitterPct: 0}
	if err := NormalizeBuildRequest(req); err != nil {
		t.Fatal(err)
	}
	if req.JitterPct != 0 {
		t.Fatalf("jitter=%d want 0", req.JitterPct)
	}
}

func TestNormalizeBuildRequestRejectsBadTiming(t *testing.T) {
	for _, req := range []*BuildRequest{
		{SleepMs: MinSleepMs - 1},
		{SleepMs: MaxSleepMs + 1},
		{JitterPct: MinJitterPct - 1},
		{JitterPct: MaxJitterPct + 1},
	} {
		if err := NormalizeBuildRequest(req); err == nil {
			t.Fatalf("expected timing error for %+v", req)
		}
	}
}

func TestNormalizeBuildRequestRejectsHTTPCallbackForHTTPS(t *testing.T) {
	err := NormalizeBuildRequest(&BuildRequest{Callbacks: []string{"http://127.0.0.1:443"}})
	if err == nil {
		t.Fatal("expected https callback error")
	}
}

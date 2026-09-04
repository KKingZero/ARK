package lateral

import (
	"sync"

	"github.com/masterzen/winrm"
)

// Persistent PTH slot: one NTLM handshake, then N SOAP commands on the same
// transport. Keyed by target|user|hash so sequential lateral winrm tasks
// do not renegotiate.
type pthSlot struct {
	mu        sync.Mutex
	transport *clientNTLMHash
	client    *winrm.Client
}

var pthPool sync.Map // string → *pthSlot

func pthSessionKey(target, domainUser, hashHex string) string {
	return target + "\x00" + domainUser + "\x00" + hashHex
}

func acquirePTHSlot(key string) *pthSlot {
	if v, ok := pthPool.Load(key); ok {
		return v.(*pthSlot)
	}
	s := &pthSlot{}
	actual, _ := pthPool.LoadOrStore(key, s)
	return actual.(*pthSlot)
}

func resetPTHPoolForTest() {
	pthPool.Range(func(k, _ any) bool {
		pthPool.Delete(k)
		return true
	})
}

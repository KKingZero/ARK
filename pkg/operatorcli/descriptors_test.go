package operatorcli

import (
	"testing"

	"github.com/KKingZero/ARK/pkg/taskmeta"
)

func TestCommandDescriptorsUseTaskMetadata(t *testing.T) {
	for _, meta := range taskmeta.All() {
		if meta.Command == "" {
			continue
		}
		d, ok := commandDescriptorByName(meta.Command)
		if !ok {
			t.Fatalf("missing descriptor for %s", meta.Command)
		}
		if d.NeedsSession != meta.NeedsSession || d.Fanout != meta.Fanout {
			t.Fatalf("%s descriptor session=%v/%v fanout=%s/%s", meta.Command, d.NeedsSession, meta.NeedsSession, d.Fanout, meta.Fanout)
		}
	}
}

func TestHandlersCoverDescriptors(t *testing.T) {
	handlers := (&Commands{}).Handlers()
	for _, d := range commandDescriptors() {
		if handlers[d.Name] == nil {
			t.Fatalf("missing handler for %s", d.Name)
		}
		if d.Usage == "" || d.Help == "" {
			t.Fatalf("descriptor %s missing usage/help", d.Name)
		}
	}
}

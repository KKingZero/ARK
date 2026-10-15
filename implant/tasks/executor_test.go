package tasks

import (
	"context"
	"testing"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/pkg/plugin"
	"github.com/KKingZero/ARK/pkg/taskmeta"
)

type stubModule struct {
	name string
}

func (m *stubModule) Name() string        { return m.name }
func (m *stubModule) Description() string { return "stub" }
func (m *stubModule) Execute(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("ok"), nil
}

func TestExecuteTypedModuleTaskTypes(t *testing.T) {
	reg := plugin.NewRegistry()
	routes := taskmeta.TypedModuleRoutes()
	for _, name := range routes {
		reg.Register(&stubModule{name: name})
	}

	e := NewExecutor(reg)
	for tt := range routes {
		result := e.Execute(&pb.Task{TaskId: "t1", TaskType: tt, Data: []byte{}})
		if !result.Success {
			t.Fatalf("%s failed: %s", tt, result.Error)
		}
		if string(result.Data) != "ok" {
			t.Fatalf("%s unexpected data: %q", tt, result.Data)
		}
	}
}

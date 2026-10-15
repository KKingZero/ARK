package taskmeta

import (
	"testing"

	pb "github.com/KKingZero/ARK/pkg/pb"
)

func TestTypedModuleRoutes(t *testing.T) {
	routes := TypedModuleRoutes()
	for typ, want := range map[pb.TaskType]string{
		pb.TaskType_TASK_CREDS_DUMP:   "creds_dump",
		pb.TaskType_TASK_LDAP_ENUM:    "ldap_enum",
		pb.TaskType_TASK_KERBEROAST:   "kerberoast",
		pb.TaskType_TASK_ASREPROAST:   "asreproast",
		pb.TaskType_TASK_LATERAL_MOVE: "lateral_move",
		pb.TaskType_TASK_PERSIST:      "persist",
		pb.TaskType_TASK_PRIVESC:      "privesc",
	} {
		if got := routes[typ]; got != want {
			t.Fatalf("%s route %q want %q", typ, got, want)
		}
	}
}

func TestCommandMetadata(t *testing.T) {
	shell, ok := ByCommand("shell")
	if !ok || !shell.NeedsSession || shell.Risk != RiskHigh {
		t.Fatalf("shell metadata = %+v ok=%v", shell, ok)
	}
	sessions, ok := ByCommand("sessions")
	if ok || sessions.NeedsSession {
		t.Fatalf("sessions should not be task metadata: %+v", sessions)
	}
}

func TestHighRiskModuleMetadata(t *testing.T) {
	for _, name := range []string{
		"creds_dump", "inject", "ldap_enum", "kerberoast", "asreproast",
		"lateral_move", "persist", "privesc", "cloud", "smb", "shell",
	} {
		meta, ok := ByModule(name)
		if !ok || (meta.Risk != RiskHigh && meta.Risk != RiskCritical) {
			t.Fatalf("%s metadata = %+v ok=%v", name, meta, ok)
		}
	}
}

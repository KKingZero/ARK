package approval

import (
	"testing"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/pkg/taskmeta"
	"google.golang.org/protobuf/proto"
)

func TestRequiresModuleApproval(t *testing.T) {
	p := DefaultPolicy()
	for _, name := range []string{
		"creds_dump", "inject", "ldap_enum", "kerberoast", "asreproast",
		"lateral_move", "persist", "privesc", "cloud", "smb", "shell",
	} {
		if !p.RequiresModuleApproval(name) {
			t.Fatalf("%s should require approval", name)
		}
	}
}

func TestDefaultPolicyMatchesTaskMetadata(t *testing.T) {
	p := DefaultPolicy()
	for _, meta := range taskmeta.All() {
		if meta.Risk != taskmeta.RiskHigh && meta.Risk != taskmeta.RiskCritical {
			continue
		}
		if meta.Type != pb.TaskType_TASK_UNKNOWN && meta.Type != pb.TaskType_TASK_MODULE && p.RiskLevel(meta.Type) != meta.Risk {
			t.Fatalf("%s risk %q want %q", meta.Type, p.RiskLevel(meta.Type), meta.Risk)
		}
		if meta.Module != "" && p.ModuleRiskLevel(meta.Module) != meta.Risk {
			t.Fatalf("%s module risk %q want %q", meta.Module, p.ModuleRiskLevel(meta.Module), meta.Risk)
		}
	}
}

func TestModuleNameFromTaskData(t *testing.T) {
	data, err := proto.Marshal(&pb.ModuleTask{ModuleName: "persist", Config: nil})
	if err != nil {
		t.Fatal(err)
	}
	if got := ModuleNameFromTaskData(data); got != "persist" {
		t.Fatalf("got %q want persist", got)
	}
}

func TestRequiresApprovalDirectTasks(t *testing.T) {
	p := DefaultPolicy()
	if !p.RequiresApproval(pb.TaskType_TASK_INJECT) {
		t.Fatal("inject should require approval")
	}
	if !p.RequiresApproval(pb.TaskType_TASK_SHELL) {
		t.Fatal("shell should require approval (balanced policy)")
	}
	if !p.RequiresApproval(pb.TaskType_TASK_FILE_UPLOAD) {
		t.Fatal("file upload should require approval")
	}
	if !p.RequiresApproval(pb.TaskType_TASK_KEYLOG_START) {
		t.Fatal("keylog_start should require approval")
	}
	if p.RequiresApproval(pb.TaskType_TASK_SCREENSHOT) {
		t.Fatal("screenshot should not require approval")
	}
	if !p.RequiresApproval(pb.TaskType_TASK_KERBEROAST) {
		t.Fatal("kerberoast should require approval")
	}
	if !p.RequiresApproval(pb.TaskType_TASK_LDAP_ENUM) {
		t.Fatal("ldap_enum should require approval")
	}
	if !p.RequiresModuleApproval("cloud") {
		t.Fatal("cloud module should require approval")
	}
}

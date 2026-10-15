package taskmeta

import (
	"strings"

	pb "github.com/KKingZero/ARK/pkg/pb"
)

const (
	RiskLow      = "low"
	RiskHigh     = "high"
	RiskCritical = "critical"
)

type FanoutMode string

const (
	FanoutNone       FanoutMode = "none"
	FanoutReadOnly   FanoutMode = "read_only"
	FanoutSingleOnly FanoutMode = "single_only"
)

type Task struct {
	Command          string
	Type             pb.TaskType
	Module           string
	Risk             string
	NeedsSession     bool
	Fanout           FanoutMode
	TypedModuleRoute string
}

var tasks = []Task{
	{Command: "shell", Type: pb.TaskType_TASK_SHELL, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutReadOnly, Module: "shell"},
	{Command: "upload", Type: pb.TaskType_TASK_FILE_UPLOAD, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "download", Type: pb.TaskType_TASK_FILE_DOWNLOAD, Risk: RiskLow, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "ps", Type: pb.TaskType_TASK_PROCESS_LIST, Risk: RiskLow, NeedsSession: true, Fanout: FanoutReadOnly},
	{Command: "kill", Type: pb.TaskType_TASK_PROCESS_KILL, Risk: RiskLow, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "ifconfig", Type: pb.TaskType_TASK_NET_IFCONFIG, Risk: RiskLow, NeedsSession: true, Fanout: FanoutReadOnly},
	{Command: "portscan", Type: pb.TaskType_TASK_NET_PORTSCAN, Risk: RiskLow, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "sleep", Type: pb.TaskType_TASK_SLEEP, Risk: RiskLow, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "screenshot", Type: pb.TaskType_TASK_SCREENSHOT, Risk: RiskLow, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "keylog", Type: pb.TaskType_TASK_KEYLOG_START, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Type: pb.TaskType_TASK_KEYLOG_STOP, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Type: pb.TaskType_TASK_KEYLOG_DUMP, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "inject", Type: pb.TaskType_TASK_INJECT, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Type: pb.TaskType_TASK_PE_LOAD, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Type: pb.TaskType_TASK_PE_LOAD_EXEC, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "socks", Type: pb.TaskType_TASK_SOCKS_START, Risk: RiskLow, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Type: pb.TaskType_TASK_SOCKS_STOP, Risk: RiskLow, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "ldap-enum", Type: pb.TaskType_TASK_LDAP_ENUM, Module: "ldap_enum", Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly, TypedModuleRoute: "ldap_enum"},
	{Command: "kerberoast", Type: pb.TaskType_TASK_KERBEROAST, Module: "kerberoast", Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly, TypedModuleRoute: "kerberoast"},
	{Command: "asreproast", Type: pb.TaskType_TASK_ASREPROAST, Module: "asreproast", Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly, TypedModuleRoute: "asreproast"},
	{Command: "creds-dump", Type: pb.TaskType_TASK_CREDS_DUMP, Risk: RiskCritical, NeedsSession: true, Fanout: FanoutSingleOnly, TypedModuleRoute: "creds_dump", Module: "creds_dump"},
	{Command: "lateral", Type: pb.TaskType_TASK_LATERAL_MOVE, Risk: RiskCritical, NeedsSession: true, Fanout: FanoutSingleOnly, TypedModuleRoute: "lateral_move", Module: "lateral_move"},
	{Command: "persist", Type: pb.TaskType_TASK_PERSIST, Risk: RiskCritical, NeedsSession: true, Fanout: FanoutSingleOnly, TypedModuleRoute: "persist", Module: "persist"},
	{Command: "privesc", Type: pb.TaskType_TASK_PRIVESC, Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly, TypedModuleRoute: "privesc", Module: "privesc"},
	{Module: "inject", Risk: RiskHigh},
	{Command: "cloud", Type: pb.TaskType_TASK_MODULE, Module: "cloud", Risk: RiskHigh, NeedsSession: true, Fanout: FanoutSingleOnly},
	{Command: "smb", Type: pb.TaskType_TASK_MODULE, Module: "smb", Risk: RiskHigh, NeedsSession: true, Fanout: FanoutReadOnly},
}

func All() []Task {
	return tasks
}

func ByType(taskType pb.TaskType) (Task, bool) {
	if taskType == pb.TaskType_TASK_MODULE {
		return Task{}, false
	}
	for _, t := range tasks {
		if t.Type == taskType {
			return t, true
		}
	}
	return Task{}, false
}

func ByCommand(command string) (Task, bool) {
	command = strings.ToLower(command)
	for _, t := range tasks {
		if t.Command == command {
			return t, true
		}
	}
	return Task{}, false
}

func ByModule(module string) (Task, bool) {
	module = strings.ToLower(module)
	for _, t := range tasks {
		if t.Module == module {
			return t, true
		}
	}
	return Task{}, false
}

func TypedModuleRoutes() map[pb.TaskType]string {
	out := map[pb.TaskType]string{}
	for _, t := range tasks {
		if t.TypedModuleRoute != "" {
			out[t.Type] = t.TypedModuleRoute
		}
	}
	return out
}

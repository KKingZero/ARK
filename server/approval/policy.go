package approval

import (
	"strings"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/pkg/taskmeta"
	"google.golang.org/protobuf/proto"
)

// Policy defines which task types require approval and their risk levels.
type Policy struct {
	HighRiskTasks   map[pb.TaskType]string // task type -> risk level
	HighRiskModules map[string]string      // module name -> risk level
}

// DefaultPolicy returns the default approval policy.
func DefaultPolicy() *Policy {
	p := &Policy{
		HighRiskTasks:   map[pb.TaskType]string{},
		HighRiskModules: map[string]string{},
	}
	for _, t := range taskmeta.All() {
		if t.Risk == taskmeta.RiskHigh || t.Risk == taskmeta.RiskCritical {
			if t.Type != pb.TaskType_TASK_MODULE && t.Type != pb.TaskType_TASK_UNKNOWN {
				p.HighRiskTasks[t.Type] = t.Risk
			}
			if t.Module != "" {
				p.HighRiskModules[t.Module] = t.Risk
			}
		}
	}
	return p
}

// RequiresApproval returns true if the task type needs operator approval.
func (p *Policy) RequiresApproval(taskType pb.TaskType) bool {
	_, ok := p.HighRiskTasks[taskType]
	return ok
}

// RiskLevel returns the risk level for a task type, or "low" if not high-risk.
func (p *Policy) RiskLevel(taskType pb.TaskType) string {
	if level, ok := p.HighRiskTasks[taskType]; ok {
		return level
	}
	return "low"
}

// RequiresModuleApproval returns true if a TASK_MODULE config targets a high-risk module.
func (p *Policy) RequiresModuleApproval(moduleName string) bool {
	_, ok := p.HighRiskModules[strings.ToLower(moduleName)]
	return ok
}

// ModuleRiskLevel returns the risk level for a module name.
func (p *Policy) ModuleRiskLevel(moduleName string) string {
	if level, ok := p.HighRiskModules[strings.ToLower(moduleName)]; ok {
		return level
	}
	return "low"
}

// ModuleNameFromTaskData extracts module_name from a TASK_MODULE payload.
func ModuleNameFromTaskData(data []byte) string {
	modTask := &pb.ModuleTask{}
	if err := proto.Unmarshal(data, modTask); err != nil {
		return ""
	}
	return modTask.ModuleName
}

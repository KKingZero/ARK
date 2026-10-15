package tasks

import (
	"context"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/KKingZero/ARK/pkg/taskmeta"
)

func (e *Executor) executeTypedModule(ctx context.Context, taskType pb.TaskType, data []byte) ([]byte, error) {
	name, ok := taskmeta.TypedModuleRoutes()[taskType]
	if !ok {
		return nil, errUnsupportedTaskType(taskType)
	}
	return e.Registry.Execute(ctx, name, data)
}

func errUnsupportedTaskType(taskType pb.TaskType) error {
	return &unsupportedTaskError{taskType: taskType}
}

type unsupportedTaskError struct {
	taskType pb.TaskType
}

func (e *unsupportedTaskError) Error() string {
	return "unsupported task type: " + e.taskType.String()
}

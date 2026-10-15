package operatorcli

import (
	"testing"

	pb "github.com/KKingZero/ARK/pkg/pb"
)

func appr(id, session string, task pb.TaskType, at int64) *pb.ApprovalRequest {
	return &pb.ApprovalRequest{
		Id:          id,
		SessionId:   session,
		TaskType:    task,
		RequestedAt: at,
	}
}

func TestSelectOneShotApprovalOneMatch(t *testing.T) {
	pending := []*pb.ApprovalRequest{
		appr("old", "s1", pb.TaskType_TASK_SHELL, 10),
		appr("other", "s2", pb.TaskType_TASK_SHELL, 100),
		appr("mine", "s1", pb.TaskType_TASK_SHELL, 100),
		nil,
	}
	id, ok := selectOneShotApproval(pending, "s1", pb.TaskType_TASK_SHELL, 50)
	if !ok || id != "mine" {
		t.Fatalf("got %q ok=%v", id, ok)
	}
}

func TestSelectOneShotApprovalNone(t *testing.T) {
	pending := []*pb.ApprovalRequest{
		appr("old", "s1", pb.TaskType_TASK_SHELL, 10),
	}
	if _, ok := selectOneShotApproval(pending, "s1", pb.TaskType_TASK_SHELL, 50); ok {
		t.Fatal("stale approval must wait")
	}
	if _, ok := selectOneShotApproval(nil, "s1", pb.TaskType_TASK_SHELL, 0); ok {
		t.Fatal("empty list must wait")
	}
	if _, ok := selectOneShotApproval(pending, "", pb.TaskType_TASK_SHELL, 0); ok {
		t.Fatal("empty session must not match")
	}
}

func TestSelectOneShotApprovalTwoMatches(t *testing.T) {
	pending := []*pb.ApprovalRequest{
		appr("a", "s1", pb.TaskType_TASK_SHELL, 100),
		appr("b", "s1", pb.TaskType_TASK_SHELL, 101),
	}
	if _, ok := selectOneShotApproval(pending, "s1", pb.TaskType_TASK_SHELL, 50); ok {
		t.Fatal("two matches must not approve")
	}
}

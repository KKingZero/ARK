package operatorcli

import (
	"context"
	"time"

	pb "github.com/KKingZero/ARK/pkg/pb"
)

// selectOneShotApproval returns the single pending approval this one-shot
// call created. Zero matches means the gate has not queued it yet. Two
// matches is ambiguous, so the caller must not approve either.
func selectOneShotApproval(pending []*pb.ApprovalRequest, sessionID string, taskType pb.TaskType, notBefore int64) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	var ids []string
	for _, a := range pending {
		if a == nil || a.GetId() == "" {
			continue
		}
		if a.GetSessionId() != sessionID || a.GetTaskType() != taskType {
			continue
		}
		if a.GetRequestedAt() < notBefore {
			continue
		}
		ids = append(ids, a.GetId())
	}
	if len(ids) != 1 {
		return "", false
	}
	return ids[0], true
}

// executeWait runs ExecuteTask. One-shot mode approves only the matching
// pending row with the approver seat while the RPC is blocked. The REPL
// leaves oneShot false, so a human still approves those tasks.
func (c *Commands) executeWait(ctx context.Context, sessionID string, taskType pb.TaskType, data []byte, timeoutMs int32) (*pb.ExecuteTaskResponse, error) {
	req := &pb.ExecuteTaskRequest{
		SessionId: sessionID,
		TaskType:  taskType,
		Data:      data,
		Wait:      true,
		TimeoutMs: int64(timeoutMs),
	}
	if !c.oneShot || c.approverClient == nil {
		return c.client.ExecuteTask(ctx, req)
	}
	type result struct {
		resp *pb.ExecuteTaskResponse
		err  error
	}
	ch := make(chan result, 1)
	notBefore := time.Now().Add(-2 * time.Second).Unix()
	go func() {
		resp, err := c.client.ExecuteTask(ctx, req)
		ch <- result{resp, err}
	}()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	poll := func() {
		list, err := c.approverClient.ListPendingApprovals(ctx, &pb.ListPendingApprovalsRequest{})
		if err != nil || list == nil {
			return
		}
		id, ok := selectOneShotApproval(list.Approvals, sessionID, taskType, notBefore)
		if !ok {
			return
		}
		_, _ = c.approverClient.Approve(ctx, &pb.ApproveRequest{ApprovalId: id})
	}
	poll()
	for {
		select {
		case r := <-ch:
			return r.resp, r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
			poll()
		}
	}
}

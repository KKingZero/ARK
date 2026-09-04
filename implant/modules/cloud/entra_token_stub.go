//go:build !windows

package cloud

import (
	"context"

	pb "github.com/KKingZero/ARK/pkg/pb"
)

func harvestEntraToken(_ context.Context) *pb.CloudHarvestResult {
	return nil
}

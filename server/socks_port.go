package server

import (
	pb "github.com/KKingZero/ARK/pkg/pb"
	"google.golang.org/protobuf/proto"
)

// socksListenPort chooses the teamserver reverse-SOCKS port.
// An empty payload, or a decoded port of 0, uses 1080. Proto3 cannot tell
// an omitted port from zero. A non-empty payload that does not decode is an error.
func socksListenPort(data []byte) (uint32, error) {
	const defaultPort uint32 = 1080
	if len(data) == 0 {
		return defaultPort, nil
	}
	var st pb.SocksStartTask
	if err := proto.Unmarshal(data, &st); err != nil {
		return 0, err
	}
	if st.Port > 0 {
		return st.Port, nil
	}
	return defaultPort, nil
}

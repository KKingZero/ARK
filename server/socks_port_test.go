package server

import (
	"testing"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"google.golang.org/protobuf/proto"
)

func TestSocksListenPort(t *testing.T) {
	got, err := socksListenPort(nil)
	if err != nil || got != 1080 {
		t.Fatalf("empty: port=%d err=%v", got, err)
	}

	raw, err := proto.Marshal(&pb.SocksStartTask{})
	if err != nil {
		t.Fatal(err)
	}
	got, err = socksListenPort(raw)
	if err != nil || got != 1080 {
		t.Fatalf("port 0: port=%d err=%v", got, err)
	}

	raw, err = proto.Marshal(&pb.SocksStartTask{Port: 9050})
	if err != nil {
		t.Fatal(err)
	}
	got, err = socksListenPort(raw)
	if err != nil || got != 9050 {
		t.Fatalf("9050: port=%d err=%v", got, err)
	}

	if _, err := socksListenPort([]byte{0xff, 0xff, 0xff, 0xff, 0x0f}); err == nil {
		t.Fatal("garbage payload decoded")
	}
}

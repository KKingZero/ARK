//go:build ignore

package main

import (
	"fmt"

	"github.com/KKingZero/ARK/pkg/arkcli"
)

func main() {
	s, err := arkcli.EnsureSeatCerts("/home/zero/.ark")
	if err != nil {
		panic(err)
	}
	fmt.Printf("op=%s ap=%s ca=%s\n", s.OperatorCert, s.ApproverCert, s.CA)
}

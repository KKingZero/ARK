package krb

import (
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/types"
)

// PA_PAC_OPTIONS is padata-type 167 (MS-KILE). gokrb5 does not define it.
const PA_PAC_OPTIONS int32 = 167

// paPACOptionsRBCD is Impacket getST encoding of PA-PAC-OPTIONS with
// resource_based_constrained_delegation (KerberosFlags bit 3).
// DER: 30 09 a0 07 03 05 00 10 00 00 00
var paPACOptionsRBCD = []byte{0x30, 0x09, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00}

type paPacOptionsEnc struct {
	Flags asn1.BitString `asn1:"explicit,tag:0"`
}

// marshalPAPacOptionsRBCD is the S4U2Proxy PA-PAC-OPTIONS getST always sends.
// Wire bytes are the Impacket golden encoding (PA-PAC-OPTIONS bit 3).
func marshalPAPacOptionsRBCD() (types.PAData, error) {
	enc := paPacOptionsEnc{
		Flags: asn1.BitString{
			Bytes:     []byte{0x10, 0x00, 0x00, 0x00},
			BitLength: 32,
		},
	}
	if _, err := asn1.Marshal(enc); err != nil {
		return types.PAData{}, fmt.Errorf("PA-PAC-OPTIONS: %w", err)
	}
	return types.PAData{
		PADataType:  PA_PAC_OPTIONS,
		PADataValue: append([]byte(nil), paPACOptionsRBCD...),
	}, nil
}

package krb

import (
	"fmt"
	"sync"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

var (
	clockMu     sync.Mutex
	clockOffset time.Duration
)

// SetClockOffset sets the process-local Kerberos clock delta (KDC - local).
func SetClockOffset(d time.Duration) {
	clockMu.Lock()
	clockOffset = d
	clockMu.Unlock()
}

// ClockOffset is KDC time minus local time.
func ClockOffset() time.Duration {
	clockMu.Lock()
	defer clockMu.Unlock()
	return clockOffset
}

// Now is UTC now plus ClockOffset (PA-ENC-TIMESTAMP / authenticator).
func Now() time.Time {
	return time.Now().UTC().Add(ClockOffset())
}

// OffsetFromSKEW is stime - local. Zero if stime is unset.
func OffsetFromSKEW(ke messages.KRBError, local time.Time) time.Duration {
	if ke.STime.IsZero() {
		return 0
	}
	if local.IsZero() {
		local = time.Now()
	}
	return ke.STime.UTC().Sub(local.UTC())
}

// ApplySKEW stores stime-local offset and reports it.
func ApplySKEW(ke messages.KRBError) time.Duration {
	d := OffsetFromSKEW(ke, time.Now())
	if d == 0 {
		return 0
	}
	SetClockOffset(d)
	return d
}

// FormatKRBError is a structured miss: errorcode=… skew_delta=…
func FormatKRBError(ke messages.KRBError) string {
	name := krbErrorName(ke.ErrorCode)
	s := fmt.Sprintf("errorcode=%s", name)
	if ke.ErrorCode == errorcode.KRB_AP_ERR_SKEW {
		d := OffsetFromSKEW(ke, time.Now())
		s += " skew_delta=" + FormatDelta(d)
		if !ke.STime.IsZero() {
			s += " stime=" + ke.STime.UTC().Format(time.RFC3339)
		}
	}
	if ke.EText != "" {
		s += " etext=" + ke.EText
	}
	return s
}

func krbErrorName(code int32) string {
	switch code {
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		return "KDC_ERR_PREAUTH_REQUIRED"
	case errorcode.KDC_ERR_PREAUTH_FAILED:
		return "KDC_ERR_PREAUTH_FAILED"
	case errorcode.KDC_ERR_ETYPE_NOSUPP:
		return "KDC_ERR_ETYPE_NOSUPP"
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return "KDC_ERR_C_PRINCIPAL_UNKNOWN"
	case errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN:
		return "KDC_ERR_S_PRINCIPAL_UNKNOWN"
	case errorcode.KRB_AP_ERR_SKEW:
		return "KRB_AP_ERR_SKEW"
	case errorcode.KDC_ERR_BADOPTION:
		return "KDC_ERR_BADOPTION"
	case errorcode.KDC_ERR_POLICY:
		return "KDC_ERR_POLICY"
	default:
		return fmt.Sprintf("%d", code)
	}
}

func bootstrapOffset(kdc string) {
	if ClockOffset() != 0 || kdc == "" {
		return
	}
	remote, err := FetchDCTime(kdc, "", "")
	if err != nil {
		return
	}
	SetClockOffset(remote.UTC().Sub(time.Now().UTC()))
}

func wrapKRB(err error) error {
	if err == nil {
		return nil
	}
	ke, ok := asKRBError(err, nil)
	if !ok {
		return err
	}
	return fmt.Errorf("%s", FormatKRBError(ke))
}

func marshalPAEncTS(at time.Time) ([]byte, error) {
	at = at.UTC()
	p := types.PAEncTSEnc{
		PATimestamp: at,
		PAUSec:      int((at.UnixNano() / int64(time.Microsecond)) - (at.Unix() * 1e6)),
	}
	return asn1.Marshal(p)
}

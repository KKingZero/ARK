package ntlmrelay

import (
	"net/url"
)

func replaceURLPath(raw, newPath string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Path = newPath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

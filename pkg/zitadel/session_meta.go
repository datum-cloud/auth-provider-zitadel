package zitadel

import (
	"strings"

	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
)

func extractUserAgentString(ua *sessionv2.UserAgent) string {
	if ua == nil {
		return ""
	}
	if d := ua.GetDescription(); d != "" {
		return d
	}
	for k, hv := range ua.GetHeader() {
		if strings.EqualFold(k, "user-agent") && hv != nil && len(hv.GetValues()) > 0 {
			return hv.GetValues()[0]
		}
	}
	return ""
}

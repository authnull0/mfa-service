package handlers

import (
	"os"
	"strings"
)

// resolveOrg returns the organisation name.
//
// Config wins so the platform works when reached by a bare IP / localhost (a host
// with no org label to parse): DOMAIN_URL (default.<org>.<domain>) then ORG_NAME.
// The request URL is used only as a fallback for multi-tenant SaaS hosts.
func resolveOrg(reqURL string) string {
	if d := os.Getenv("DOMAIN_URL"); d != "" {
		if p := strings.Split(d, "."); len(p) > 1 {
			return p[1]
		}
	}
	if v := os.Getenv("ORG_NAME"); v != "" {
		return v
	}
	if p := strings.Split(reqURL, "."); len(p) > 1 {
		return p[1]
	}
	return ""
}

// resolveTenant returns the tenant name, with the same config-first precedence as
// resolveOrg: DOMAIN_URL (default.<org>.<domain>) then the request URL as fallback.
func resolveTenant(reqURL string) string {
	if d := os.Getenv("DOMAIN_URL"); d != "" {
		if p := strings.Split(d, "."); len(p) > 0 {
			return p[0]
		}
	}
	if p := strings.Split(reqURL, "."); len(p) > 0 {
		return p[0]
	}
	return ""
}

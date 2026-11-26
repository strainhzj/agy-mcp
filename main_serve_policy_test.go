package main

import (
	"strings"
	"testing"

	"github.com/tphakala/agy-mcp/v2/internal/config"
	"github.com/tphakala/agy-mcp/v2/internal/policy"
)

// protectedServeConfig is the least configuration a protected profile can
// start with over HTTP: token-bearing, loopback-bound.
func protectedServeConfig() config.Config {
	return config.Config{
		Policy: policy.Policy{
			Profile:          policy.ProfilePi,
			RequireHTTPToken: true,
		},
		HTTPToken: "secret",
	}
}

// TestValidateServeStartup pins the startup-order contract: the HTTP bind and
// the final token are judged before any manager exists, so a refused server
// never restores jobs or starts probes. Removing the RequireHTTPToken branch
// (or the protected stdio refusal) turns the matching case red.
func TestValidateServeStartup(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.Config
		addr    string
		wantErr string // "" means it must pass
	}{
		{"unrestricted stdio passes", config.Config{}, "", ""},
		{"unrestricted http without token passes", config.Config{}, "127.0.0.1:8765", ""},
		{"protected stdio refused", protectedServeConfig(), "", "Streamable HTTP only"},
		{"protected http passes", protectedServeConfig(), "127.0.0.1:8765", ""},
		{"protected http without token refused", func() config.Config {
			c := protectedServeConfig()
			c.HTTPToken = ""
			return c
		}(), "127.0.0.1:8765", "empty token cannot start"},
		{"require token flag without token refused", config.Config{
			Policy: policy.Policy{RequireHTTPToken: true},
		}, "127.0.0.1:8765", "empty token cannot start"},
		{"require token with token passes", config.Config{
			Policy:    policy.Policy{RequireHTTPToken: true},
			HTTPToken: "secret",
		}, "127.0.0.1:8765", ""},
		{"require token in stdio mode passes", config.Config{
			Policy: policy.Policy{RequireHTTPToken: true},
		}, "", ""},
		{"non-loopback bind refused", config.Config{}, "0.0.0.0:8765", "loopback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServeStartup(tc.cfg, tc.addr)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateServeStartup(%s) = %v, want nil", tc.addr, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateServeStartup(%s) = %v, want an error containing %q", tc.addr, err, tc.wantErr)
			}
		})
	}
}

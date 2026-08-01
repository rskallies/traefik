package snicheck

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	traefiktcp "github.com/traefik/traefik/v3/pkg/tcp"
)

func TestSNICheck_ServeHTTP(t *testing.T) {
	testCases := []struct {
		desc                string
		tlsOptionsName      string
		tlsOptionsNameInCtx string
		echAccepted         bool
		host                string
		serverName          string
		expected            int
	}{
		{
			desc:                "same TLS options",
			tlsOptionsName:      "foo",
			tlsOptionsNameInCtx: "foo",
			expected:            http.StatusOK,
		},
		{
			desc:                "different TLS options",
			tlsOptionsName:      "foo",
			tlsOptionsNameInCtx: "bar",
			expected:            http.StatusMisdirectedRequest,
		},
		{
			desc: "ECH accepted, decrypted SNI matches Host: TLS options mismatch in ctx is ignored",
			// The outer (pre-decryption) SNI resolved a different router than the
			// decrypted inner Host, so the ctx-based TLSOptionsName legitimately
			// diverges from the router's. That's expected with ECH and must not 421.
			tlsOptionsName:      "inner-options",
			tlsOptionsNameInCtx: "outer-options",
			echAccepted:         true,
			host:                "example.com",
			serverName:          "example.com",
			expected:            http.StatusOK,
		},
		{
			desc:                "ECH accepted, decrypted SNI does not match Host",
			tlsOptionsName:      "inner-options",
			tlsOptionsNameInCtx: "outer-options",
			echAccepted:         true,
			host:                "example.com",
			serverName:          "attacker.example",
			expected:            http.StatusMisdirectedRequest,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			sniCheck := New("test-router", test.tlsOptionsName, next)

			req := httptest.NewRequest(http.MethodGet, "https://localhost", nil)
			if test.host != "" {
				req.Host = test.host
			}
			req.TLS = &tls.ConnectionState{
				ServerName:  test.serverName,
				ECHAccepted: test.echAccepted,
			}

			ctx := traefiktcp.AddTLSOptionsNameInContext(req.Context(), test.tlsOptionsNameInCtx)
			req = req.WithContext(ctx)

			recorder := httptest.NewRecorder()

			sniCheck.ServeHTTP(recorder, req)

			assert.Equal(t, test.expected, recorder.Code)
		})
	}
}

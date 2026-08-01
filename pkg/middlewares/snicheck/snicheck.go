package snicheck

import (
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/middlewares/requestdecorator"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

// SNICheck is an HTTP handler that checks whether the TLS configuration for the server name is the same as for the host header.
type SNICheck struct {
	next           http.Handler
	routerName     string
	tlsOptionsName string
}

// New creates a new SNICheck.
func New(routerName, tlsOptionsName string, next http.Handler) *SNICheck {
	return &SNICheck{
		next:           next,
		routerName:     routerName,
		tlsOptionsName: tlsOptionsName,
	}
}

func (s SNICheck) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.TLS == nil {
		s.next.ServeHTTP(rw, req)
		return
	}

	// With ECH, the TCP-layer TLSOptionsName recorded in ctx is resolved from the
	// outer (pre-decryption) SNI, since that's all that's visible before the TLS
	// handshake runs. The HTTP router's tlsOptionsName is resolved from the
	// decrypted inner Host/SNI. These are expected to differ by ECH's design, so
	// the ctx-based comparison below produces a false positive here. Fall back to
	// comparing the decrypted SNI against the Host header directly instead, which
	// is what this check did before ECH support existed.
	if req.TLS.ECHAccepted {
		host := getHost(req)
		serverName := strings.TrimSpace(req.TLS.ServerName)
		if !strings.EqualFold(host, serverName) {
			log.Debug().
				Str("routerName", s.routerName).
				Str("req.Host", req.Host).
				Str("req.TLS.ServerName", req.TLS.ServerName).
				Msg("ECH: Host/SNI mismatch after decryption")
			http.Error(rw, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
			return
		}

		s.next.ServeHTTP(rw, req)
		return
	}

	tlsOptionsNameUsed := tcp.GetTLSOptionsName(req.Context())
	if s.tlsOptionsName != tlsOptionsNameUsed {
		log.Debug().
			Str("routerName", s.routerName).
			Str("req.Host", req.Host).
			Str("req.TLS.ServerName", req.TLS.ServerName).
			Msgf("TLS options difference: SNI:%s, Header:%s", tlsOptionsNameUsed, s.tlsOptionsName)
		http.Error(rw, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return
	}

	s.next.ServeHTTP(rw, req)
}

func getHost(req *http.Request) string {
	h := requestdecorator.GetCNAMEFlatten(req.Context())
	if h != "" {
		return h
	}

	h = requestdecorator.GetCanonicalHost(req.Context())
	if h != "" {
		return h
	}

	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}

	return strings.TrimSpace(host)
}

package tlsconfig

import (
	"crypto/tls"
	"testing"
)

func TestLocalServerTLSConfigUsesHTTP1Only(t *testing.T) {
	t.Parallel()

	cfg := LocalServerTLSConfig()
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 minimum, got %x", cfg.MinVersion)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("expected HTTP/1.1 only, got %v", cfg.NextProtos)
	}
}

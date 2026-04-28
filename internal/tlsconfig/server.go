package tlsconfig

import "crypto/tls"

// LocalServerTLSConfig returns the TLS settings for the embedded local API server.
func LocalServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{
			"http/1.1",
		},
	}
}

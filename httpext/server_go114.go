//go:build go1.14
// +build go1.14

package httpext

import (
	"crypto/tls"
	"strings"
)

func CipherSuites() []*tls.CipherSuite {
	return tls.CipherSuites()
}

// TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

func SetCipherSuites(cfg *tls.Config, values string) {
	SetCipherSuitesWithNames(cfg, strings.Split(values, ","))
}

func SetCipherSuitesWithNames(cfg *tls.Config, values []string) {
	cfg.CipherSuites = nil
	for _, name := range values {
		name = strings.TrimSpace(name)
		name = strings.ToUpper(name)

		for _, cipherSuite := range tls.CipherSuites() {
			if cipherSuite.Name == name {
				cfg.CipherSuites = append(cfg.CipherSuites, cipherSuite.ID)
				break
			}
		}
		for _, cipherSuite := range tls.InsecureCipherSuites() {
			if cipherSuite.Name == name {
				cfg.CipherSuites = append(cfg.CipherSuites, cipherSuite.ID)
				break
			}
		}
	}
}

package main

import (
	"fmt"
	"math/rand"
	"strings"

	tls "github.com/refraction-networking/utls"
)

func normalizeTLSFingerprint(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto", "rotate":
		return "rotate"
	case "chrome", "firefox", "ios", "randomized", "randomized-no-alpn":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "rotate"
	}
}

func chooseTLSFingerprint(mode string) string {
	if mode != "rotate" {
		return mode
	}
	choices := []string{"chrome", "firefox", "randomized"}
	return choices[rand.Intn(len(choices))]
}

func clientHelloID(fingerprint string) tls.ClientHelloID {
	switch fingerprint {
	case "chrome":
		return tls.HelloChrome_Auto
	case "firefox":
		return tls.HelloFirefox_Auto
	case "ios":
		return tls.HelloIOS_Auto
	case "randomized-no-alpn":
		return tls.HelloRandomizedNoALPN
	default:
		return tls.HelloRandomizedALPN
	}
}

func cipherSuiteName(id uint16) string {
	switch id {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xc02b:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xc02f:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xc02c:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xc030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xcca9:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	case 0xcca8:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("0x%04x", id)
	}
}

package gotak

import (
	"crypto/x509"
	"fmt"
)

const (
	TLS_1_0 = 10
	TLS_1_1 = 11
	TLS_1_2 = 12
)

func cryptVersTlsToGotak(vers uint16) (int, error) {
	switch vers {
	case 0x0300, 0x0301:
		return TLS_1_0, nil
	case 0x0302:
		return TLS_1_1, nil
	case 0x0303:
		return TLS_1_2, nil
	default:
		return -1, fmt.Errorf("Error: Could not parse version %d.", vers)
	}
}

type Diagnostics struct {
	Version      int
	CipherSuite  string
	Certificates []*x509.Certificate
	NPN          bool
	NpnStrings   []string
}

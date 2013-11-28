package gotak

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
)

type TlsVersion uint16

const (
	TLS_1_0 TlsVersion = 10
	TLS_1_1            = 11
	TLS_1_2            = 12
)

func (t TlsVersion) String() string {
	switch t {
	case TLS_1_0:
		return "1.0"
	case TLS_1_1:
		return "1.1"
	case TLS_1_2:
		return "1.2"
	default:
		return ""
	}
}

func cryptVersTlsToGotak(vers uint16) (TlsVersion, error) {
	switch vers {
	case 0x0300, 0x0301:
		return TLS_1_0, nil
	case 0x0302:
		return TLS_1_1, nil
	case 0x0303:
		return TLS_1_2, nil
	default:
		return 0, fmt.Errorf("Error: Could not parse version %d.", vers)
	}
}

type Diagnostics struct {
	Version      TlsVersion
	CipherSuite  string
	Certificates []*x509.Certificate
	NPN          bool
	NpnStrings   []string
}

func (d *Diagnostics) JSON() ([]byte, error) {
	jd := new(jsonDiagnostics)
	jd.Version = d.Version.String()
	jd.CipherSuite = d.CipherSuite
	jd.NPN = d.NpnStrings

	return json.Marshal(jd)
}

func (d *Diagnostics) EncodeJSON(w io.Writer) error {
	jd := new(jsonDiagnostics)
	jd.Version = d.Version.String()
	jd.CipherSuite = d.CipherSuite
	jd.NPN = d.NpnStrings

	return json.NewEncoder(w).Encode(jd)
}

type jsonDiagnostics struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	NPN         []string `json:"next_protocol_negotiation,omitempty"`
}

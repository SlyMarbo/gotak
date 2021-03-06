package gotak

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
)

type Diagnostics struct {
	Version      TlsVersion
	CipherSuite  string
	Certificates []*x509.Certificate
	NPN          bool
	NpnStrings   []string
}

func Diagnose(addr string, config *Config) (*Diagnostics, error) {
	if config == nil {
		config = new(Config)
		config.NextProtos = []string{"http/1.1"}
	}

	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}

	conn, diag, err := Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	clientConn := httputil.NewClientConn(conn, nil)

	req, err := http.NewRequest("GET", "/favicon.ico", nil)
	if err != nil {
		return nil, err
	}

	clientConn.Do(req)

	if diag.NpnStrings != nil {
		diag.NPN = true
	}

	return diag, nil
}

func DiagnoseRequest(r *http.Request, config *Config) (*Diagnostics, error) {
	if config == nil {
		config = new(Config)
		config.NextProtos = []string{"http/1.1"}
	}

	addr := r.URL.Host

	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}

	conn, diag, err := Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	clientConn := httputil.NewClientConn(conn, nil)

	clientConn.Do(r)

	if diag.NpnStrings != nil {
		diag.NPN = true
	}

	return diag, nil
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
	case VersionSSL30, VersionTLS10:
		return TLS_1_0, nil
	case VersionTLS11:
		return TLS_1_1, nil
	case VersionTLS12:
		return TLS_1_2, nil
	default:
		return 0, fmt.Errorf("Error: Could not parse version %d.", vers)
	}
}

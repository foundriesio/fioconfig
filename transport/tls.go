package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/foundriesio/fioconfig/sotatoml"
)

// importPath resolves a path read from the [import] block. When the
// configured value is relative, it is joined onto import.base_path
// the same way lmp-device-register and the aktualizr clients treat
// these keys. Without this fix, relative paths fall back to the
// process CWD and TLS fails with a confusing missing-file error.
func importPath(cfg *sotatoml.AppConfig, key string) string {
	p := cfg.Get(key)
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	base := cfg.Get("import.base_path")
	if base == "" {
		return p
	}
	return filepath.Join(base, p)
}

func GetTlsConfig(cfg *sotatoml.AppConfig) (*tls.Config, interface{}, error) {
	if val := cfg.Get("tls.ca_source"); val != "file" {
		return nil, nil, fmt.Errorf("invalid tls.ca_source: %s", val)
	}

	caCertPool := x509.NewCertPool()
	caFile := importPath(cfg, "import.tls_cacert_path")
	if len(caFile) == 0 {
		return nil, nil, fmt.Errorf("import.tls_cacert_path not configured")
	}
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read CA cert: %w", err)
	}
	caCertPool.AppendCertsFromPEM(caCert)

	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{},
		RootCAs:      caCertPool,
	}

	var extra interface{}
	source := cfg.Get("tls.pkey_source")
	if source == "file" {
		if cert, err := loadCertLocal(cfg); err == nil {
			tlsCfg.Certificates = []tls.Certificate{cert}
		} else {
			return nil, nil, err
		}
	} else if source == "pkcs11" {
		if ctx, cert, err := loadCertPkcs11(cfg); err == nil {
			tlsCfg.Certificates = []tls.Certificate{cert}
			extra = ctx
		} else {
			return nil, nil, err
		}
	} else {
		return nil, nil, fmt.Errorf("invalid tls.pkey_source: %s", source)
	}

	return &tlsCfg, extra, nil
}

func loadCertLocal(cfg *sotatoml.AppConfig) (tls.Certificate, error) {
	keyFile := importPath(cfg, "import.tls_pkey_path")
	certFile := importPath(cfg, "import.tls_clientcert_path")
	if len(keyFile) == 0 {
		return tls.Certificate{}, fmt.Errorf("import.tls_pkey_path not specified")
	}
	if len(certFile) == 0 {
		return tls.Certificate{}, fmt.Errorf("import.tls_clientcert_path not specified")
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

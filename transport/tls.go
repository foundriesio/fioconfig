package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/ThalesIgnite/crypto11"

	"github.com/foundriesio/fioconfig/sotatoml"
)

func GetTlsConfig(cfg *sotatoml.AppConfig) (*tls.Config, interface{}, error) {
	if val := cfg.Get("tls.ca_source"); val != "file" {
		return nil, nil, fmt.Errorf("invalid tls.ca_source: %s", val)
	}

	caCertPool := x509.NewCertPool()
	caFile := cfg.Get("import.tls_cacert_path")
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
	keyFile := cfg.Get("import.tls_pkey_path")
	certFile := cfg.Get("import.tls_clientcert_path")
	if len(keyFile) == 0 {
		return tls.Certificate{}, fmt.Errorf("import.tls_pkey_path not specified")
	}
	if len(certFile) == 0 {
		return tls.Certificate{}, fmt.Errorf("import.tls_clientcert_path not specified")
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func loadCertPkcs11(cfg *sotatoml.AppConfig) (*crypto11.Context, tls.Certificate, error) {
	module := cfg.Get("p11.module")
	pin := cfg.Get("p11.pass")
	pkeyId := cfg.Get("p11.tls_pkey_id")
	certId := cfg.Get("p11.tls_clientcert_id")
	if len(module) == 0 || len(pin) == 0 || len(pkeyId) == 0 || len(certId) == 0 {
		return nil, tls.Certificate{}, fmt.Errorf("missing required p11 configs for: module, pass, tls_pkey_id, and/or tls_clientcert_id")
	}

	c11 := crypto11.Config{
		Path:        module,
		TokenLabel:  cfg.GetDefault("p11.label", "aktualizr"),
		Pin:         pin,
		MaxSessions: 2,
	}

	ctx, err := crypto11.Configure(&c11)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("unable to load crypto11 config: %w", err)
	}

	privKey, err := ctx.FindKeyPair(sotatoml.IdToBytes(pkeyId), nil)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("unable to load pkcs11 private key: %w", err)
	}
	cert, err := ctx.FindCertificate(sotatoml.IdToBytes(certId), nil, nil)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("unable to load pkcs11 client certificate: %w", err)
	}
	return ctx, tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privKey,
	}, nil
}

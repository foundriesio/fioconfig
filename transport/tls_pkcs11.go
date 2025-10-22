//go:build !disable_pkcs11

package transport

import (
	"crypto/tls"
	"fmt"

	"github.com/ThalesIgnite/crypto11"

	"github.com/foundriesio/fioconfig/sotatoml"
)

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

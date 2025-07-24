//go:build disable_pkcs11

package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"

	ecies "github.com/foundriesio/go-ecies"
)

var ErrNoPkcs11 = errors.New("DeleteKeyPair not supported in local ECIES handler")

type EciesCrypto struct {
	PrivKey ecies.KeyProvider
}

func NewEciesLocalHandler(privKey crypto.PrivateKey) CryptoHandler {
	if ec, ok := privKey.(*ecdsa.PrivateKey); ok {
		return &EciesCrypto{ecies.ImportECDSA(ec)}
	}
	return nil
}

func (ec *EciesCrypto) Decrypt(value string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("Unable to base64 decode: %v", err)
	}
	decrypted, err := ecies.Decrypt(ec.PrivKey, data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to ECIES decrypt %v", err)
	}
	return decrypted, nil
}

func (ec *EciesCrypto) Encrypt(value string) (string, error) {
	enc, err := ecies.Encrypt(rand.Reader, ec.PrivKey.Public(), []byte(value), nil, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

func (ec *EciesCrypto) UsePkcs11() bool {
	return false
}

func (ec *EciesCrypto) DeleteKeyPair(id []byte, label []byte) error {
	return ErrNoPkcs11
}

func (ec *EciesCrypto) DeleteCertificate(id []byte, label []byte, serial *big.Int) error {
	return ErrNoPkcs11
}

func (ec *EciesCrypto) ImportCertificateWithLabel(id []byte, label []byte, certificate *x509.Certificate) error {
	return ErrNoPkcs11
}

func (ec *EciesCrypto) GenerateKeyPair(id []byte, label []byte) (crypto.Signer, error) {
	return nil, ErrNoPkcs11
}

func (ec *EciesCrypto) Close() {
}

func NewEciesPkcs11Handler(ctx any, privKey crypto.PrivateKey) CryptoHandler {
	log.Fatal("NewEciesPkcs11Handler should not be called in disable_pkcs11 build")
	return nil
}

func getPkcs11CryptoHandler(h *certRotationContext) (*EciesCrypto, error) {
	log.Fatal("getPkcs11CryptoHandler should not be called in disable_pkcs11 build")
	return nil, nil
}

package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/ThalesIgnite/crypto11"
	ecies "github.com/foundriesio/go-ecies"
	"github.com/miekg/pkcs11"
)

type EciesCrypto struct {
	PrivKey ecies.KeyProvider
	ctx     *crypto11.Context
}

func NewEciesLocalHandler(privKey crypto.PrivateKey) CryptoHandler {
	if ec, ok := privKey.(*ecdsa.PrivateKey); ok {
		return &EciesCrypto{ecies.ImportECDSA(ec), nil}
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
	return ec.ctx != nil
}

func (ec *EciesCrypto) DeleteKeyPair(id []byte, label []byte) error {
	return ec.ctx.DeleteKeyPair(id, label)
}

func (ec *EciesCrypto) DeleteCertificate(id []byte, label []byte, serial *big.Int) error {
	return ec.ctx.DeleteCertificate(id, label, serial)
}

func (ec *EciesCrypto) ImportCertificateWithLabel(id []byte, label []byte, certificate *x509.Certificate) error {
	return ec.ctx.ImportCertificateWithLabel(id, label, certificate)
}

func (ec *EciesCrypto) GenerateKeyPair(id []byte, label []byte) (crypto.Signer, error) {
	if err := ec.ctx.DeleteKeyPair(id, label); err != nil {
		return nil, fmt.Errorf("Unable to free up slot(%s) for new keypair: %w", id, err)
	}
	pubAttr, err := crypto11.NewAttributeSetWithIDAndLabel(id, []byte("tls"))
	if err != nil {
		return nil, fmt.Errorf("Unable to define pkcs11 attributes for new key: %w", err)
	}
	// The default ecdsa logic in crypto11 does not include the ability to
	// derive which is required for ECIES decryption
	pubAttr.AddIfNotPresent([]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true)})
	privAttr := pubAttr.Copy()
	signer, err := ec.ctx.GenerateECDSAKeyPairWithAttributes(pubAttr, privAttr, elliptic.P256())
	if err != nil {
		return nil, fmt.Errorf("Unable to generate new keypair in HSM: %w", err)
	}
	return signer, nil
}

func (ec *EciesCrypto) Close() {
	if ec.ctx != nil {
		ec.ctx.Close()
	}
}

func NewEciesPkcs11Handler(ctx *crypto11.Context, privKey crypto.PrivateKey) CryptoHandler {
	return &EciesCrypto{ImportPcks11(ctx, privKey), ctx}
}

type PrivateKeyPkcs11 struct {
	*ecies.PublicKey
	ctx    *crypto11.Context
	signer crypto11.Signer
}

func ImportPcks11(ctx *crypto11.Context, privKey crypto.PrivateKey) *PrivateKeyPkcs11 {
	signer := privKey.(crypto11.Signer)
	pub := signer.Public().(*ecdsa.PublicKey)
	return &PrivateKeyPkcs11{ecies.ImportECDSAPublic(pub), ctx, signer}
}

func (prv *PrivateKeyPkcs11) GenerateShared(pub *ecies.PublicKey) (sk []byte, err error) {
	return prv.ctx.ECDH1Derive(prv.signer, pub.ExportECDSA())
}

func (prv *PrivateKeyPkcs11) Public() *ecies.PublicKey {
	return prv.PublicKey
}

package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
	"github.com/umbracle/ecies"
)

type EciesCrypto struct {
	PrivKey PrivateKey
	ctx     *crypto11.Context
}

func NewEciesLocalHandler(privKey crypto.PrivateKey) CryptoHandler {
	if ec, ok := privKey.(*ecdsa.PrivateKey); ok {
		return &EciesCrypto{ImportECDSA(ec), nil}
	}
	return nil
}

func (ec *EciesCrypto) Decrypt(value string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("Unable to base64 decode: %v", err)
	}
	decrypted, err := EciesDecrypt(ec.PrivKey, data, nil, nil)
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

func (ec *EciesCrypto) Close() {
	if ec.ctx != nil {
		ec.ctx.Close()
	}
}

func NewEciesPkcs11Handler(ctx *crypto11.Context, privKey crypto11.Signer) CryptoHandler {
	return &EciesCrypto{ImportPcks11(ctx, privKey), ctx}
}

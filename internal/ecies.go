package internal

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type EciesCrypto struct {
	PrivKey *ecies.PrivateKey
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
	decrypted, err := ec.PrivKey.Decrypt(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to ECIES decrypt %v", err)
	}
	return decrypted, nil
}

func NewEciesPkcs11Handler(privKey crypto11.Signer) CryptoHandler {
	panic("NOT IMPLEMENTED")
}

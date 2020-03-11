package internal

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type App struct {
	PrivKey         *ecies.PrivateKey
	EncryptedConfig string
	SecretsDir      string
}

func NewApp(sota_config, secrets_dir string) (*App, error) {
	path := filepath.Join(sota_config, "pkey.pem") // TODO from sota.toml
	pkey_pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to read private key: %v", err)
	}

	block, _ := pem.Decode(pkey_pem)
	if block == nil {
		return nil, fmt.Errorf("Unable to decode private key(%s): %v", path, err)
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse private key(%s): %v", path, err)
	}

	app := App{
		PrivKey:         ecies.ImportECDSA(priv.(*ecdsa.PrivateKey)),
		EncryptedConfig: filepath.Join(sota_config, "config.encrypted"),
		SecretsDir:      secrets_dir,
	}

	return &app, nil
}

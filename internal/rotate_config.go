package internal

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
)

type fullCfgStep struct{}

func (s fullCfgStep) Name() string {
	return "Update local configuration with new key"
}

func (s fullCfgStep) Execute(handler *CertRotationHandler) error {
	crypto, err := getCryptoHandler(handler)
	if err != nil {
		return err
	}
	defer crypto.Close()

	// Open/decrypt full config with current key
	config, err := UnmarshallFile(handler.crypto, handler.app.EncryptedConfig, true)
	if err != nil {
		return fmt.Errorf("Unable open current encrypted config: %w", err)
	}

	// Encrypt with new key
	for _, cfgFile := range config {
		if !cfgFile.Unencrypted {
			val, err := crypto.Encrypt(cfgFile.Value)
			if err != nil {
				return fmt.Errorf("Unable to re-encrypt config: %w", err)
			}
			cfgFile.Value = val
		}
	}
	val, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("Unexpected error marshalling config: %w", err)
	}
	handler.State.FullConfigEncrypted = string(val)
	return nil
}

func getCryptoHandler(h *CertRotationHandler) (*EciesCrypto, error) {
	if !h.usePkcs11() {
		block, _ := pem.Decode([]byte(h.State.NewKey))
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse new private key: %w", err)
		}
		return NewEciesLocalHandler(key).(*EciesCrypto), nil
	}

	module := tomlGet(h.app.sota, "p11.module")
	pin := tomlGet(h.app.sota, "p11.pass")

	cfg := crypto11.Config{
		Path:        module,
		TokenLabel:  h.app.sota.GetDefault("p11.label", "aktualizr").(string),
		Pin:         pin,
		MaxSessions: 2,
	}

	ctx, err := crypto11.Configure(&cfg)
	if err != nil {
		return nil, fmt.Errorf("Unable to configure crypto11 library: %w", err)
	}

	privKey, err := ctx.FindKeyPair(idToBytes(h.State.NewKey), nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to find new HSM private key: %w", err)
	}
	return NewEciesPkcs11Handler(ctx, privKey).(*EciesCrypto), nil
}

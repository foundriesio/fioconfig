package internal

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/ThalesIgnite/crypto11"
	"github.com/foundriesio/fioconfig/sotatoml"
)

type fullCfgStep struct{}

func (s fullCfgStep) Name() string {
	return "Update local configuration with new key"
}

func (s fullCfgStep) Execute(handler *certRotationContext) error {
	crypto, err := getCryptoHandler(handler)
	if err != nil {
		return err
	}
	defer crypto.Close()

	// Open/decrypt full config with current key
	config, err := UnmarshallFile(handler.crypto, handler.app.EncryptedConfig, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) { // os.IsNotExist does not work on wrapped errors
			return nil
		}
		return fmt.Errorf("Unable open current encrypted config: %w", err)
	}

	// Encrypt with new key
	cfgBytes, err := encryptConfig(crypto, config)
	if err != nil {
		return err
	}
	handler.State.FullConfigEncrypted = string(cfgBytes)
	return nil
}

type deviceCfgStep struct{}

func (s deviceCfgStep) Name() string {
	return "Update device specific configuration on server with new key"
}

func (s deviceCfgStep) Execute(handler *certRotationContext) error {
	// Load the new crypto handler
	crypto, err := getCryptoHandler(handler)
	if err != nil {
		return err
	}
	defer crypto.Close()
	pub := crypto.PrivKey.Public()
	pubDer, err := x509.MarshalPKIXPublicKey(pub.ExportECDSA())
	if err != nil {
		return err
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	// Download/decrypt current device config with current key
	url := handler.app.configUrl + "-device"
	res, err := httpGet(handler.client, url, nil)
	if err != nil {
		return err
	}
	if res.StatusCode == 204 {
		// Device has no configuration
		handler.State.DeviceConfigUpdated = true
		return nil
	} else if res.StatusCode != 200 {
		return fmt.Errorf("Unable to get device configuration: HTTP_%d - %s", res.StatusCode, res.String())
	}
	config, err := UnmarshallBuffer(handler.crypto, res.Body, true)
	if err != nil {
		log.Printf("Unable to decrypt device config with old key, trying new key: %s", err)
		// There's a chance that we'd uploaded this config with the new key and
		// had a power failure before we saved the state to disk. Check if
		// we can decrypt with that key before giving up.
		if _, err = UnmarshallBuffer(crypto, res.Body, true); err == nil {
			// We just failed to save the state. We are good.
			handler.State.DeviceConfigUpdated = true
			return nil
		} else {
			return err
		}
	}

	// Encrypt with new key
	if _, err := encryptConfig(crypto, config); err != nil {
		return err
	}

	// Upload to server
	ccr := ConfigCreateRequest{
		Reason: "Rotating device client certificate",
		PubKey: string(pubPem),
	}
	for name, entry := range config {
		ccr.Files = append(ccr.Files, ConfigFileReq{
			Name:        name,
			Value:       entry.Value,
			Unencrypted: entry.Unencrypted,
			OnChanged:   entry.OnChanged,
		})
	}
	res, err = httpPatch(handler.client, handler.app.configUrl, ccr)
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 204 {
		return fmt.Errorf("Unable to patch device config: HTTP_%d - %s", res.StatusCode, res.String())
	}
	handler.State.DeviceConfigUpdated = true
	return nil
}

func encryptConfig(crypto *EciesCrypto, config map[string]*ConfigFile) ([]byte, error) {
	for _, cfgFile := range config {
		if !cfgFile.Unencrypted {
			val, err := crypto.Encrypt(cfgFile.Value)
			if err != nil {
				return nil, fmt.Errorf("Unable to re-encrypt config: %w", err)
			}
			cfgFile.Value = val
		}
	}
	val, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("Unexpected error marshalling config: %w", err)
	}
	return val, nil
}

func getCryptoHandler(h *certRotationContext) (*EciesCrypto, error) {
	if !h.usePkcs11() {
		block, _ := pem.Decode([]byte(h.State.NewKey))
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse new private key: %w", err)
		}
		return NewEciesLocalHandler(key).(*EciesCrypto), nil
	}

	module := h.app.sota.GetOrDie("p11.module")
	pin := h.app.sota.GetOrDie("p11.pass")

	cfg := crypto11.Config{
		Path:        module,
		TokenLabel:  h.app.sota.GetDefault("p11.label", "aktualizr"),
		Pin:         pin,
		MaxSessions: 2,
	}

	ctx, err := crypto11.Configure(&cfg)
	if err != nil {
		return nil, fmt.Errorf("Unable to configure crypto11 library: %w", err)
	}

	privKey, err := ctx.FindKeyPair(sotatoml.IdToBytes(h.State.NewKey), nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to find new HSM private key: %w", err)
	}
	return NewEciesPkcs11Handler(ctx, privKey).(*EciesCrypto), nil
}

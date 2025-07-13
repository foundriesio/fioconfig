package internal

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/foundriesio/fioconfig/transport"
)

type lockStep struct{}

type DeviceUpdate struct {
	NextPubKey string `json:"next_pubkey"`
}

func (s lockStep) Name() string {
	return "Lock device configuration on server"
}

func (s lockStep) Execute(handler *certRotationContext) error {
	crypto, err := getCryptoHandler(handler)
	if err != nil {
		return err
	}
	pub := crypto.PrivKey.Public()
	crypto.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(pub.ExportECDSA())
	if err != nil {
		return err
	}

	pubBytes = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	url := handler.app.sota.GetOrDie("tls.server") + "/device"
	if res, err := transport.HttpPatch(handler.client, url, DeviceUpdate{string(pubBytes)}); err != nil {
		return err
	} else if res.StatusCode != 200 {
		return fmt.Errorf("Unable to set device's next public key: HTTP_%d - %s", res.StatusCode, res.String())
	}
	return nil
}

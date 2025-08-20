//go:build vpn
// +build vpn

package internal

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foundriesio/fioconfig/transport"
)

// Create a private key and return the derived public key
func generateKey(privKeyPath string) (string, error) {
	pkey, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", err
	}

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = bytes.NewBuffer(pkey)

	pub, err := cmd.Output()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(privKeyPath, pkey, 0600); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(pub)), nil
}

func vpnBugFix(app *App, sotaConfig string) bool {
	// We had a race condition fixed in commit f4baae04cdf381d0a61a46c1f64c774f54020256
	// However, we have devices in the field that were already in a bad
	// state. This logic exists to fix them. Eventually, all those devices
	// will pick up this OTA, and we'll be able to remove this quirk.
	secretFile := filepath.Join(app.SecretsDir, "wireguard-client")
	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		log.Println("Wireguard key not registered on server, will re-register")
		return true
	}
	return false
}

func initVpn(app *App, client *http.Client, crypto CryptoHandler) error {
	wgPriv := filepath.Join(app.StorageDir, "wg-priv")
	register := false
	if _, err := os.Stat(wgPriv); os.IsNotExist(err) {
		register = true
		log.Println("Wireguard private key does not exist, generating.")
	} else {
		register = vpnBugFix(app, app.StorageDir)
	}
	if register {
		wgPrivTmp := wgPriv + ".tmp"
		pub, err := generateKey(wgPrivTmp)
		if err != nil {
			return fmt.Errorf("Unable to generate private key: %s", err)
		}
		log.Printf("Uploading Wireguard pub key(%s).", pub)
		if err := updateVpnConfig(app, client, pub); err != nil {
			return fmt.Errorf("Unable to server config with VPN public key: %s", err)
		}
		if err = os.Rename(wgPrivTmp, wgPriv); err != nil {
			return fmt.Errorf("Unable to write wireguard private key: %s", err)
		}
	}
	return nil
}

func updateVpnConfig(app *App, client *http.Client, pubkey string) error {
	updated := ""
	content, err := os.ReadFile(filepath.Join(app.SecretsDir, "wireguard-client"))
	if err != nil {
		if os.IsNotExist(err) {
			updated = "enabled=0\n" // This isn't enabled
		} else {
			return err
		}
	}
	written := false

	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "pubkey=") {
			updated += "pubkey=" + pubkey + "\n"
			written = true
		} else {
			updated += line + "\n"
		}
	}
	if !written {
		updated += "pubkey=" + pubkey + "\n"
	}
	updated = strings.TrimSpace(updated)

	ccr := ConfigCreateRequest{
		Reason: "Set Wireguard pubkey from fioconfig",
		Files: []ConfigFileReq{
			{
				Name:        "wireguard-client",
				Unencrypted: true,
				Value:       updated,
			},
		},
	}
	res, err := transport.HttpPatch(client, app.configUrl, ccr)
	if err != nil {
		return err
	}
	if res.StatusCode != 201 {
		return fmt.Errorf("Unable to update: %s - HTTP_%d: %s", app.configUrl, res.StatusCode, string(res.Body))
	}
	return nil
}

func init() {
	initFunctions["wireguard-vpn"] = initVpn
}

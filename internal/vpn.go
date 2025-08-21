//go:build vpn
// +build vpn

package internal

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type vpnInitCallback struct {
}

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

func (v *vpnInitCallback) ConfigFiles(app *App) []ConfigFileReq {
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
			log.Printf("Unable to generate private key: %s", err)
			return nil
		}
		files, err := getVpnCfgFiles(app, pub)
		if err != nil {
			log.Printf("Unable to generate VPN config files: %s", err)
			return nil
		}
		return files
	}

	// prevent init logic from calling OnComplete by removing ourselves
	delete(initCallbacks, "wireguard-vpn")
	return nil
}

func (v vpnInitCallback) OnComplete(app *App) {
	wgPriv := filepath.Join(app.StorageDir, "wg-priv")
	if err := os.Rename(wgPriv+".tmp", wgPriv); err != nil {
		log.Printf("Unable to write wireguard private key: %s", err)
		return
	}
	delete(initCallbacks, "wireguard-vpn")
}

func getVpnCfgFiles(app *App, pubkey string) ([]ConfigFileReq, error) {
	updated := ""
	content, err := os.ReadFile(filepath.Join(app.SecretsDir, "wireguard-client"))
	if err != nil {
		if os.IsNotExist(err) {
			updated = "enabled=0\n" // This isn't enabled
		} else {
			return nil, err
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

	files := []ConfigFileReq{
		{
			Name:        "wireguard-client",
			Unencrypted: true,
			Value:       updated,
		},
	}
	return files, nil
}

func init() {
	initCallbacks["wireguard-vpn"] = &vpnInitCallback{}
}

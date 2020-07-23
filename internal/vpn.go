// +build vpn

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ConfigFileReq struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Unencrypted bool     `json:"unencrypted"`
	OnChanged   []string `json:"on-changed,omitempty"`
}

type ConfigCreateRequest struct {
	Reason string          `json:"reason"`
	Files  []ConfigFileReq `json:"files"`
}

// Create a private key and return the derived public key
func generateKey(privKeyPath string) (string, error) {
	pkey, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", err
	}

	cmd := exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer stdin.Close()
		stdin.Write(pkey)
	}()

	pub, err := cmd.Output()
	if err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(privKeyPath, pkey, 0600); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(pub)), nil

}

func updateConfig(app *App, client *http.Client, pubkey string) error {
	updated := ""
	content, err := ioutil.ReadFile(filepath.Join(app.SecretsDir, "wireguard-client"))
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

	data, err := json.Marshal(ConfigCreateRequest{
		Reason: "Set Wireguard pubkey from fioconfig",
		Files: []ConfigFileReq{
			ConfigFileReq{
				Name:        "wireguard-client",
				Unencrypted: true,
				Value:       updated,
			},
		},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", app.configUrl, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Unable to update: %s - %v", app.configUrl, err)
	}
	if res.StatusCode != 201 {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("Unable to update: %s - HTTP_%d", app.configUrl, res.StatusCode, string(msg))
	}
	return nil
}

func initVpn(app *App, client *http.Client, crypto CryptoHandler) error {
	sotaConfig := filepath.Dir(app.EncryptedConfig)
	wgPriv := filepath.Join(sotaConfig, "wg-priv")
	if _, err := os.Stat(wgPriv); os.IsNotExist(err) {
		log.Println("Wireguard private key does not exist, generating.")
		pub, err := generateKey(wgPriv)
		if err != nil {
			return fmt.Errorf("Unable to generate private key: %s", err)
		}
		log.Printf("Uploading Wireguard pub key(%s).", pub)
		if err := updateConfig(app, client, pub); err != nil {
			os.Remove(wgPriv)
			return fmt.Errorf("Unable to server config with VPN public key: %s", err)
		}
	}
	return nil
}

func init() {
	initFunctions["wireguard-vpn"] = initVpn
}

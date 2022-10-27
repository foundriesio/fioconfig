package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var Commit string

type ConfigFile struct {
	Value       string
	OnChanged   []string
	Unencrypted bool
}

type ConfigStruct = map[string]*ConfigFile

func UnmarshallFile(c CryptoHandler, encFile string, decrypt bool) (ConfigStruct, error) {
	content, err := os.ReadFile(encFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read encrypted file: %w", err)
	}
	return UnmarshallBuffer(c, content, decrypt)
}

func UnmarshallBuffer(c CryptoHandler, encContent []byte, decrypt bool) (ConfigStruct, error) {
	var config map[string]*ConfigFile
	if err := json.Unmarshal(encContent, &config); err != nil {
		return nil, fmt.Errorf("Unable to parse encrypted json: %v", err)
	}
	if decrypt {
		for fname, cfgFile := range config {
			if !cfgFile.Unencrypted {
				log.Printf("Decoding value of %s", fname)
				decrypted, err := c.Decrypt(cfgFile.Value)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", fname, err)
				}
				cfgFile.Value = string(decrypted)
			}
		}
	}
	return config, nil
}

type ConfigFileReq struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Unencrypted bool     `json:"unencrypted"`
	OnChanged   []string `json:"on-changed,omitempty"`
}

type ConfigCreateRequest struct {
	Reason string          `json:"reason"`
	Files  []ConfigFileReq `json:"files"`
	PubKey string          `json:"public-key"`
}

func updateConfig(app *App, client *http.Client, pubkey string) error {
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
	res, err := httpPatch(client, app.configUrl, ccr)
	if err != nil {
		return err
	}
	if res.StatusCode != 201 {
		return fmt.Errorf("Unable to update: %s - HTTP_%d: %s", app.configUrl, res.StatusCode, string(res.Body))
	}
	return nil
}

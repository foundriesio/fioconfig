package internal

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
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
				slog.Info("Decoding value", "file", fname)
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

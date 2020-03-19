package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

var Commit string

type ConfigFile struct {
	Value       string
	OnChanged   []string
	Unencrypted bool
}

func Unmarshall(ecPriv *ecies.PrivateKey, encFile string) (map[string]*ConfigFile, error) {
	content, err := ioutil.ReadFile(encFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read encrypted file: %w", err)
	}

	var config map[string]*ConfigFile
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("Unable to parse encrypted json: %v", err)
	}
	for fname, cfgFile := range config {
		if !cfgFile.Unencrypted {
			log.Printf("Decoding value of %s", fname)
			data, err := base64.StdEncoding.DecodeString(cfgFile.Value)
			if err != nil {
				return nil, fmt.Errorf("Unable to decode %s: %v", fname, err)
			}
			decrypted, err := ecPriv.Decrypt(data, nil, nil)
			if err != nil {
				return nil, fmt.Errorf("Unable to decrypt %s: %v", fname, err)
			}
			cfgFile.Value = string(decrypted)
		}
	}
	return config, nil
}

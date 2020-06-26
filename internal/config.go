package internal

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
)

var Commit string

type ConfigFile struct {
	Value       string
	OnChanged   []string
	Unencrypted bool
}

func Unmarshall(c CryptoHandler, encFile string) (map[string]*ConfigFile, error) {
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
			decrypted, err := c.Decrypt(cfgFile.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", fname, err)
			}
			cfgFile.Value = string(decrypted)
		}
	}
	return config, nil
}

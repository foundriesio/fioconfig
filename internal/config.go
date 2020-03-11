package internal

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

var Commit string

type ConfigFile struct {
	Value    []byte
	OnChange string
}

func Unmarshall(ecPriv *ecies.PrivateKey, encFile string) (map[string]*ConfigFile, error) {
	content, err := ioutil.ReadFile(encFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read encrypted file: %v", err)
	}

	var config map[string]*ConfigFile
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("Unable to parse encrypted json: %v", err)
	}

	for fname, cfgFile := range config {
		log.Printf("Decoding value of %s", fname)
		decrypted, err := ecPriv.Decrypt(cfgFile.Value, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("Unable to decrypt %s: %v", fname, err)
		}
		cfgFile.Value = decrypted
	}
	return config, nil
}

package internal

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"testing"
)

const pub_pem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2Lk7kpRnR3lJez9536ADaNtrDYIc
pUk69sabVt61KujrrN/57RQWfRHzc2wbU/mit/ndbbQVuYSZPlOwYKP96A==
-----END PUBLIC KEY-----`

const pkey_pem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3crfB0FprBSTYR+g
NMpyLSTSUBfiixurSy3gsgXSeDChRANCAATYuTuSlGdHeUl7P3nfoANo22sNghyl
STr2xptW3rUq6Ous3/ntFBZ9EfNzbBtT+aK3+d1ttBW5hJk+U7Bgo/3o
-----END PRIVATE KEY-----`

func encrypt(t *testing.T, config map[string]*ConfigFile) {
	block, _ := pem.Decode([]byte(pub_pem))
	if block == nil {
		t.Fatalf("failed to parse certificate PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse DER encoded public key: %s", err)
	}

	ecpub := pub.(*ecdsa.PublicKey)
	eciesPub := ecies.ImportECDSAPublic(ecpub)

	for fname, cfgFile := range config {
		enc, err := ecies.Encrypt(rand.Reader, eciesPub, cfgFile.Value, nil, nil)
		if err != nil {
			t.Fatalf("Unable to encrypt %s: %s", fname, err)
		}
		cfgFile.Value = enc
	}
}

func testWrapper(t *testing.T, testFunc func(app *App)) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	if err := ioutil.WriteFile(filepath.Join(dir, "pkey.pem"), []byte(pkey_pem), 0644); err != nil {
		t.Fatal(err)
	}

	config := make(map[string]*ConfigFile)
	config["foo"] = &ConfigFile{Value: []byte("foo file value")}
	config["bar"] = &ConfigFile{Value: []byte("bar file value")}
	random := make([]byte, 1024) // 1MB random file
	_, err = rand.Read(random)
	if err != nil {
		t.Fatalf("Unable to create random buffer: %v", err)
	}
	config["random"] = &ConfigFile{Value: random}

	encrypt(t, config)
	if string(config["foo"].Value) == "foo file value" {
		t.Fatal("Encryption did not occur")
	}
	app, err := NewApp(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(app.EncryptedConfig, b, 0644); err != nil {
		t.Fatal(err)
	}
	testFunc(app)
}

func TestUnmarshall(t *testing.T) {
	testWrapper(t, func(app *App) {
		unmarshalled, err := Unmarshall(app.PrivKey, app.EncryptedConfig)
		if err != nil {
			t.Fatal(err)
		}
		if string(unmarshalled["foo"].Value) != "foo file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if string(unmarshalled["bar"].Value) != "bar file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if len(unmarshalled["random"].Value) != 1024 {
			t.Fatal("Invalid random unmarshalling")
		}
	})
}
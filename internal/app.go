package internal

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type App struct {
	PrivKey         *ecies.PrivateKey
	EncryptedConfig string
	SecretsDir      string

	client    *http.Client
	configUrl string
}

func createClient(sota_config string) *http.Client {
	certFile := filepath.Join(sota_config, "client.pem")
	keyFile := filepath.Join(sota_config, "pkey.pem")
	caFile := filepath.Join(sota_config, "root.crt")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport}
}

func NewApp(sota_config, secrets_dir string) (*App, error) {
	path := filepath.Join(sota_config, "pkey.pem") // TODO from sota.toml
	pkey_pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to read private key: %v", err)
	}

	block, _ := pem.Decode(pkey_pem)
	if block == nil {
		return nil, fmt.Errorf("Unable to decode private key(%s): %v", path, err)
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse private key(%s): %v", path, err)
	}

	app := App{
		PrivKey:         ecies.ImportECDSA(priv.(*ecdsa.PrivateKey)),
		EncryptedConfig: filepath.Join(sota_config, "config.encrypted"),
		SecretsDir:      secrets_dir,
		client:          createClient(sota_config),
		configUrl:       "https://ota-lite.foundries.io:8443/config/",
	}

	return &app, nil
}

func (a *App) Extract() error {
	if _, err := os.Stat(a.SecretsDir); err != nil {
		return err
	}
	config, err := Unmarshall(a.PrivKey, a.EncryptedConfig)
	if err != nil {
		return err
	}

	for fname, cfgFile := range config {
		log.Printf("Extracting %s", fname)
		if err := ioutil.WriteFile(filepath.Join(a.SecretsDir, fname), cfgFile.Value, 0644); err != nil {
			return fmt.Errorf("Unable to extract %s: %v", fname, err)
		}
	}
	return nil
}

// Do an atomic change to the secrets file so that a reader of the current
// secrets file won't hit race conditions.
func safeWrite(input io.ReadCloser, path string) error {
	defer input.Close()

	safepath := path + ".tmp"
	to, err := os.OpenFile(safepath, os.O_RDWR|os.O_CREATE, 0644)
	defer to.Close()
	if err != nil {
		return fmt.Errorf("Unable to create new secrets: %s - %w", path, err)
	}

	_, err = io.Copy(to, input)
	if err != nil {
		return fmt.Errorf("Unable to copy secrets to: %s - %w", path, err)
	}

	if err := os.Rename(safepath, path); err != nil {
		return fmt.Errorf("Unable to link secrets to: %s - %w", path, err)
	}
	return nil
}

func (a *App) CheckIn() error {
	res, err := a.client.Get(a.configUrl)
	if err != nil {
		return fmt.Errorf("Unable to get: %s - %v", a.configUrl, err)
	}
	if res.StatusCode == 200 {
		if err := safeWrite(res.Body, a.EncryptedConfig); err != nil {
			return err
		}
	} else {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("Unable to get %s - HTTP_%d: %s", a.configUrl, res.StatusCode, string(msg))
	}
	return a.Extract()
}

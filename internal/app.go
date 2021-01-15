package internal

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ThalesIgnite/crypto11"
	toml "github.com/pelletier/go-toml"
)

var NotModifiedError = errors.New("Config unchanged on server")

// Functions to be called when the daemon is initialized
var initFunctions = map[string]func(app *App, client *http.Client, crypto CryptoHandler) error{}

type CryptoHandler interface {
	Decrypt(value string) ([]byte, error)
	Close()
}

type App struct {
	EncryptedConfig string
	EncryptedBackup string
	SecretsDir      string

	configUrl string
	sota      *toml.Tree
}

func tomlGet(tree *toml.Tree, key string) string {
	val := tree.GetDefault(key, "").(string)
	if len(val) == 0 {
		fmt.Println("ERROR: Missing", key, "in sota.toml")
		os.Exit(1)
	}
	return val
}

func tomlAssertVal(tree *toml.Tree, key string, allowed []string) string {
	val := tomlGet(tree, key)
	for _, v := range allowed {
		if val == v {
			return val
		}
	}
	fmt.Println("ERROR: Invalid value", val, "in sota.toml for", key)
	return val
}

// sota.toml has slot id's as "01". We need to turn that into []byte{1}
func idToBytes(id string) []byte {
	bytes := []byte(id)
	start := -1
	for idx, char := range bytes {
		bytes[idx] = char - byte('0')
		if bytes[idx] != 0 && start == -1 {
			start = idx
		}
	}
	//strip off leading 0's
	return bytes[start:]
}

func createClientPkcs11(sota *toml.Tree) (*http.Client, CryptoHandler) {
	module := tomlGet(sota, "p11.module")
	pin := tomlGet(sota, "p11.pass")
	pkeyId := tomlGet(sota, "p11.tls_pkey_id")
	certId := tomlGet(sota, "p11.tls_clientcert_id")
	caFile := tomlGet(sota, "import.tls_cacert_path")

	cfg := crypto11.Config{
		Path:        module,
		TokenLabel:  "aktualizr",
		Pin:         pin,
		MaxSessions: 2,
	}

	ctx, err := crypto11.Configure(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := ctx.FindKeyPair(idToBytes(pkeyId), nil)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := ctx.FindCertificate(idToBytes(certId), nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	if cert == nil || privKey == nil {
		log.Fatal("Unable to load pkcs11 client cert and/or private key")
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  privKey,
			},
		},
		RootCAs: caCertPool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Timeout: time.Second * 30, Transport: transport}
	return client, NewEciesPkcs11Handler(ctx, privKey)
}

func createClientLocal(sota *toml.Tree) (*http.Client, CryptoHandler) {
	certFile := tomlGet(sota, "import.tls_clientcert_path")
	keyFile := tomlGet(sota, "import.tls_pkey_path")
	caFile := tomlGet(sota, "import.tls_cacert_path")

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
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Timeout: time.Second * 30, Transport: transport}

	if handler := NewEciesLocalHandler(cert.PrivateKey); handler != nil {
		return client, handler
	}
	panic("Unsupported private key")
}

func createClient(sota *toml.Tree) (*http.Client, CryptoHandler) {
	_ = tomlAssertVal(sota, "tls.ca_source", []string{"file"})
	source := tomlAssertVal(sota, "tls.pkey_source", []string{"file", "pkcs11"})
	_ = tomlAssertVal(sota, "tls.cert_source", []string{source})
	if source == "file" {
		return createClientLocal(sota)
	}
	return createClientPkcs11(sota)
}

func NewApp(sota_config, secrets_dir string, testing bool) (*App, error) {
	sota, err := toml.LoadFile(filepath.Join(sota_config, "sota.toml"))
	if err != nil {
		fmt.Println("ERROR - unable to decode sota.toml:", err)
		os.Exit(1)
	}
	// Assert we have a sane configuration
	_, crypto := createClient(sota)
	crypto.Close()

	url := os.Getenv("CONFIG_URL")
	if len(url) == 0 {
		url = sota.GetDefault("tls.server", "https://ota-lite.foundries.io:8443").(string)
		url += "/config"
	}

	app := App{
		EncryptedConfig: filepath.Join(sota_config, "config.encrypted"),
		EncryptedBackup: filepath.Join(sota_config, "config.encrypted.bak"),
		SecretsDir:      secrets_dir,
		configUrl:       url,
		sota:            sota,
	}

	return &app, nil
}

// Do an atomic update of the file if needed
func updateSecret(secretFile string, newContent []byte) (bool, error) {
	curContent, err := ioutil.ReadFile(secretFile)
	if err == nil && bytes.Equal(newContent, curContent) {
		return false, nil
	}
	tmp := secretFile + ".tmp"
	if err := ioutil.WriteFile(tmp, newContent, 0640); err != nil {
		return true, fmt.Errorf("Unable to create %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, secretFile); err != nil {
		return true, fmt.Errorf("Unable to update secret: %s - %w", secretFile, err)
	}
	return true, nil
}

func (a *App) extract(crypto CryptoHandler) error {
	if _, err := os.Stat(a.SecretsDir); err != nil {
		return err
	}
	config, err := Unmarshall(crypto, a.EncryptedConfig, true)
	if err != nil {
		return err
	}

	all_fname := make(map[string]bool)
	for fname, cfgFile := range config {
		log.Printf("Extracting %s", fname)
		all_fname[fname] = true
		fullpath := filepath.Join(a.SecretsDir, fname)
		changed, err := updateSecret(fullpath, []byte(cfgFile.Value))
		if err != nil {
			return err
		}
		if changed {
			runOnChanged(fname, fullpath, cfgFile.OnChanged)
		}
	}

	// Now, watch for file removals (compare with previous version)
	if _, err := os.Stat(a.EncryptedBackup); err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return err
		}
	}
	prev, err := Unmarshall(nil, a.EncryptedBackup, false)
	if err != nil {
		return err
	}
	for fname, cfgFile := range prev {
		if _, ok := all_fname[fname]; ok {
			continue
		}
		log.Printf("Removing %s", fname)
		fullpath := filepath.Join(a.SecretsDir, fname)
		if err := os.Remove(fullpath); err != nil {
			return err
		}
		runOnChanged(fname, fullpath, cfgFile.OnChanged)
	}

	return nil
}

func (a *App) Extract() error {
	_, crypto := createClient(a.sota)
	defer crypto.Close()
	return a.extract(crypto)
}

func close(c io.Closer, name string) {
	err := c.Close()
	if err != nil {
		log.Printf("Unexpected error closing %s: %s", name, err)
	}
}

// Do an atomic change to the secrets file so that a reader of the current
// secrets file won't hit race conditions.
func safeWrite(input io.ReadCloser, path string, modtime time.Time) error {
	defer close(input, path)

	safepath := path + ".tmp"
	to, err := os.OpenFile(safepath, os.O_RDWR|os.O_CREATE, 0644)
	defer close(to, safepath)
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

	err = os.Chtimes(path, modtime, modtime)
	if err != nil {
		return fmt.Errorf("Unable to set modified time %s - %w", path, err)
	}
	return nil
}

func runOnChanged(fname string, fullpath string, onChanged []string) {
	if len(onChanged) > 0 {
		log.Printf("Running on-change command for %s: %v", fname, onChanged)
		cmd := exec.Command(onChanged[0], onChanged[1:]...)
		cmd.Env = append(os.Environ(), "CONFIG_FILE="+fullpath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Unable to run command: %v", err)
		}
	}
}

func (a *App) checkin(client *http.Client, crypto CryptoHandler) error {
	req, err := http.NewRequest("GET", a.configUrl, nil)
	if err != nil {
		return err
	}
	req.Close = true

	fi, err := os.Stat(a.EncryptedConfig)
	exists := !os.IsNotExist(err)
	if err == nil {
		// Don't pull it down unless we need to
		ts := fi.ModTime().UTC().Format(time.RFC1123)
		req.Header.Add("If-Modified-Since", ts)
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Unable to get: %s - %v", a.configUrl, err)
	}
	if res.StatusCode == 200 {
		if exists {
			if err := os.Rename(a.EncryptedConfig, a.EncryptedBackup); err != nil {
				log.Printf("Unable to backup previous config version: %s", err)
				return err
			}
		}
		modtime, err := time.Parse(time.RFC1123, res.Header.Get("Date"))
		if err != nil {
			log.Printf("Unable to get modtime of config file, defaulting to 'now': %s", err)
			modtime = time.Now()
		}
		if err := safeWrite(res.Body, a.EncryptedConfig, modtime); err != nil {
			return err
		}
	} else if res.StatusCode == 304 {
		log.Println("Config on server has not changed")
		return NotModifiedError
	} else if res.StatusCode == 204 {
		log.Println("Device has no config defined on server")
		return NotModifiedError
	} else {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("Unable to get %s - HTTP_%d: %s", a.configUrl, res.StatusCode, string(msg))
	}
	return a.extract(crypto)
}

func (a *App) CheckIn() error {
	client, crypto := createClient(a.sota)
	defer crypto.Close()
	return a.checkin(client, crypto)
}

func (a *App) CallInitFunctions() error {
	client, crypto := createClient(a.sota)
	defer crypto.Close()

	for name, cb := range initFunctions {
		log.Printf("Running %s initialization", name)
		if err := cb(a, client, crypto); err != nil {
			return err
		}
	}
	return nil
}

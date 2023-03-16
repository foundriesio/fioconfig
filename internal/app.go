package internal

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ThalesIgnite/crypto11"
	toml "github.com/pelletier/go-toml"
)

const onChangedForceExit = 123

var NotModifiedError = errors.New("Config unchanged on server")

// Functions to be called when the daemon is initialized
var initFunctions = map[string]func(app *App, client *http.Client, crypto CryptoHandler) error{}

type CryptoHandler interface {
	Decrypt(value string) ([]byte, error)
	Close()
}

type configSnapshot struct {
	prev ConfigStruct
	next ConfigStruct
}

type App struct {
	EncryptedConfig string
	SecretsDir      string

	configUrl      string
	unsafeHandlers bool
	sota           *toml.Tree

	exitFunc func(int)
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
		TokenLabel:  sota.GetDefault("p11.label", "aktualizr").(string),
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

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
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

	caCert, err := os.ReadFile(caFile)
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

func NewApp(sota_config, secrets_dir string, unsafeHandlers, testing bool) (*App, error) {
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
		SecretsDir:      secrets_dir,
		configUrl:       url,
		sota:            sota,
		unsafeHandlers:  unsafeHandlers,
		exitFunc:        os.Exit,
	}

	return &app, nil
}

// Do an atomic update of the file if needed
func updateSecret(secretFile string, newContent []byte) (bool, error) {
	curContent, err := os.ReadFile(secretFile)
	if err == nil && bytes.Equal(newContent, curContent) {
		return false, nil
	}
	return true, safeWrite(secretFile, newContent)
}

// Do an atomic write to the file which prevents race conditions for a reader.
// Don't worry about writer synchronization as there is only one writer to these files.
func safeWrite(name string, data []byte) error {
	tmpfile := name + ".tmp"
	f, err := os.OpenFile(tmpfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("Unable to create %s: %w", name, err)
	}
	defer os.Remove(tmpfile)
	_, err = f.Write(data)
	if err1 := f.Sync(); err1 != nil && err == nil {
		err = err1
	}
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}

	if err != nil {
		return fmt.Errorf("Unable to create %s: %w", name, err)
	}
	return os.Rename(tmpfile, name)
}

func (a *App) extract(crypto CryptoHandler, config configSnapshot) error {
	st, err := os.Stat(a.SecretsDir)
	if err != nil {
		return err
	}

	all_fname := make(map[string]bool)
	for fname, cfgFile := range config.next {
		log.Printf("Extracting %s", fname)
		all_fname[fname] = true
		fullpath := filepath.Join(a.SecretsDir, fname)
		dirName := filepath.Dir(fullpath)
		if err := os.MkdirAll(dirName, st.Mode()); err != nil {
			return fmt.Errorf("Unable to create parent directory secret: %s - %w", fullpath, err)
		}
		changed, err := updateSecret(fullpath, []byte(cfgFile.Value))
		if err != nil {
			return err
		}
		if changed {
			a.runOnChanged(fname, fullpath, cfgFile.OnChanged)
		}
	}

	// Now, watch for file removals (compare with a previous version if present)
	if config.prev == nil {
		return nil
	}
	for fname, cfgFile := range config.prev {
		if _, ok := all_fname[fname]; ok {
			continue
		}
		log.Printf("Removing %s", fname)
		fullpath := filepath.Join(a.SecretsDir, fname)
		if err := os.Remove(fullpath); err != nil && !os.IsNotExist(err) {
			return err
		}
		a.runOnChanged(fname, fullpath, cfgFile.OnChanged)
	}
	if err := DeleteEmptyDirs(a.SecretsDir); err != nil {
		log.Printf("ERROR removing empty directories: %s", err)
	}
	return nil
}

func (a *App) Extract() error {
	_, crypto := createClient(a.sota)
	defer crypto.Close()

	config, err := UnmarshallFile(crypto, a.EncryptedConfig, true)
	if err != nil {
		return err
	}
	return a.extract(crypto, configSnapshot{nil, config})
}

func (a *App) runOnChanged(fname string, fullpath string, onChanged []string) {
	path, err := os.Readlink("/proc/self/exe")
	if err != nil {
		log.Printf("Unable to find path to self via /proc/self/exe: %s", err)
	}
	if len(onChanged) > 0 {
		binary := filepath.Clean(onChanged[0])
		if a.unsafeHandlers || strings.HasPrefix(binary, "/usr/share/fioconfig/handlers/") {
			log.Printf("Running on-change command for %s: %v", fname, onChanged)
			cmd := exec.Command(onChanged[0], onChanged[1:]...)
			cmd.Env = append(os.Environ(), "CONFIG_FILE="+fullpath)
			cmd.Env = append(cmd.Env, "SOTA_DIR="+tomlGet(a.sota, "storage.path"))
			cmd.Env = append(cmd.Env, "FIOCONFIG_BIN="+path)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Printf("Unable to run command: %v", err)
				if exitError, ok := err.(*exec.ExitError); ok {
					if exitError.ExitCode() == onChangedForceExit {
						a.exitFunc(onChangedForceExit)
					}
				}
			}
		} else {
			log.Printf("Skipping unsafe on-change command for %s: %v.", fname, onChanged)
		}
	}
}

func (a *App) checkin(client *http.Client, crypto CryptoHandler) error {
	headers := make(map[string]string)

	if fi, err := os.Stat(a.EncryptedConfig); err == nil {
		// Don't pull it down unless we need to
		ts := fi.ModTime().UTC().Format(time.RFC1123)
		headers["If-Modified-Since"] = ts
	}

	res, err := httpGet(client, a.configUrl, headers)
	if err != nil {
		return err // Unable to attempt request
	}

	if res.StatusCode == 200 {
		var config configSnapshot
		if config.next, err = UnmarshallBuffer(crypto, res.Body, true); err != nil {
			return err
		}
		if config.prev, err = UnmarshallFile(nil, a.EncryptedConfig, false); err != nil {
			var perr *os.PathError
			if !errors.As(err, &perr) || !os.IsNotExist(perr) {
				log.Printf("Unable to load previous config version: %s", err)
				return err
			}
		}

		if err = a.extract(crypto, config); err != nil {
			return err
		}
		if err = safeWrite(a.EncryptedConfig, res.Body); err != nil {
			return err
		}

		modtime, err := time.Parse(time.RFC1123, res.Header.Get("Date"))
		if err != nil {
			log.Printf("Unable to get modtime of config file, defaulting to 'now': %s", err)
			modtime = time.Now()
		}
		if err = os.Chtimes(a.EncryptedConfig, modtime, modtime); err != nil {
			return fmt.Errorf("Unable to set modified time %s - %w", a.EncryptedConfig, err)
		}
		return nil
	} else if res.StatusCode == 304 {
		log.Println("Config on server has not changed")
		return NotModifiedError
	} else if res.StatusCode == 204 {
		log.Println("Device has no config defined on server")
		return NotModifiedError
	}
	return fmt.Errorf("Unable to get %s - HTTP_%d: %s", a.configUrl, res.StatusCode, res.String())
}

func (a *App) CheckIn() error {
	client, crypto := createClient(a.sota)
	defer crypto.Close()
	a.callInitFunctions(client, crypto)
	return a.checkin(client, crypto)
}

func (a *App) CallInitFunctions() {
	client, crypto := createClient(a.sota)
	defer crypto.Close()
	a.callInitFunctions(client, crypto)
}

func (a *App) callInitFunctions(client *http.Client, crypto CryptoHandler) {
	for name, cb := range initFunctions {
		log.Printf("Running %s initialization", name)
		if err := cb(a, client, crypto); err != nil {
			log.Println("ERROR:", err)
		} else {
			delete(initFunctions, name)
		}
	}
}

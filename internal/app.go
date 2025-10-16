package internal

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/foundriesio/fioconfig/fiotest"
	"github.com/foundriesio/fioconfig/sotatoml"
	"github.com/foundriesio/fioconfig/transport"
)

const onChangedForceExit = 123

var NotModifiedError = errors.New("Config unchanged on server")

type CryptoHandler interface {
	Decrypt(value string) ([]byte, error)
	Close()
}

type configSnapshot struct {
	prev ConfigStruct
	next ConfigStruct
}

type App struct {
	StorageDir      string
	EncryptedConfig string
	SecretsDir      string

	configUrl      string
	configPaths    []string
	unsafeHandlers bool
	sota           *sotatoml.AppConfig

	exitFunc func(int)
}

func createClient(cfg *sotatoml.AppConfig) (*http.Client, CryptoHandler) {
	tlsCfg, extra, err := transport.GetTlsConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{Timeout: time.Second * 30, Transport: transport}

	if "file" == cfg.Get("tls.pkey_source") {
		if handler := NewEciesLocalHandler(tlsCfg.Certificates[0].PrivateKey); handler != nil {
			return client, handler
		}
		log.Fatal("unsupported private key")
	}
	return client, NewEciesPkcs11Handler(extra, tlsCfg.Certificates[0].PrivateKey)
}

func NewApp(configPaths []string, secrets_dir string, unsafeHandlers, testing bool) (*App, error) {
	if len(configPaths) == 0 {
		configPaths = sotatoml.DEF_CONFIG_ORDER
	}
	sota, err := sotatoml.NewAppConfig(configPaths)
	if err != nil {
		fmt.Println("ERROR - unable to decode sota.toml:", err)
		os.Exit(1)
	}
	// Assert we have a sane configuration
	_, crypto := createClient(sota)
	crypto.Close()

	url := os.Getenv("CONFIG_URL")
	if len(url) == 0 {
		url = sota.GetDefault("tls.server", "https://ota-lite.foundries.io:8443")
		url += "/config"
	}

	storagePath := sota.GetOrDie("storage.path")

	app := App{
		StorageDir:      storagePath,
		EncryptedConfig: filepath.Join(storagePath, "config.encrypted"),
		SecretsDir:      secrets_dir,
		configUrl:       url,
		configPaths:     configPaths,
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
	return true, sotatoml.SafeWrite(secretFile, newContent)
}

func (a *App) extract(config configSnapshot) error {
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
	return a.extract(configSnapshot{nil, config})
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
			cmd.Env = append(cmd.Env, "STORAGE_DIR="+a.StorageDir)
			cmd.Env = append(cmd.Env, "SOTA_DIR="+strings.Join(a.configPaths, ","))
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
	var config configSnapshot
	var err error

	if config.prev, err = UnmarshallFile(nil, a.EncryptedConfig, false); err != nil {
		var perr *os.PathError
		if !errors.As(err, &perr) || !os.IsNotExist(perr) {
			log.Printf("Unable to load previous config version: %s. Forcing config update", err)
		}
	} else if fi, err := os.Stat(a.EncryptedConfig); err == nil {
		// Don't pull it down unless we need to
		ts := fi.ModTime().UTC().Format(time.RFC1123)
		headers["If-Modified-Since"] = ts
	}

	res, err := transport.HttpGet(client, a.configUrl, headers)
	if err != nil {
		return err // Unable to attempt request
	}

	if res.StatusCode == 200 {
		if config.next, err = UnmarshallBuffer(crypto, res.Body, true); err != nil {
			return err
		}

		if err = a.extract(config); err != nil {
			return err
		}
		if err = sotatoml.SafeWrite(a.EncryptedConfig, res.Body); err != nil {
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
	callInitFunctions(a, client)
	return a.checkin(client, crypto)
}

func (a *App) RunAndReport(name, testId, artifactsDir string, args []string) error {
	client, crypto := createClient(a.sota)
	defer crypto.Close()

	url := a.sota.GetDefault("tls.server", "https://ota-lite.foundries.io:8443")
	url += "/tests"
	api := fiotest.NewApi(client, url)

	test, err := api.Create(name, testId)
	if err != nil {
		return fmt.Errorf("Unable to create test record: %w", err)
	}
	tr := fiotest.ExecCommand(args, artifactsDir)
	if err := test.Complete(tr); err != nil {
		return fmt.Errorf("Unable to complete test record: %w", err)
	}
	return nil
}

func (a *App) CallInitFunctions() {
	client, crypto := createClient(a.sota)
	defer crypto.Close()
	callInitFunctions(a, client)
}

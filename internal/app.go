package internal

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
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
var HandlersDir = "/usr/share/fioconfig/handlers/"

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
	unsafeHandlers bool
	sota           *sotatoml.AppConfig

	exitFunc func(int)
}

func createClient(cfg *sotatoml.AppConfig) (*http.Client, CryptoHandler) {
	tlsCfg, extra, err := transport.GetTlsConfig(cfg)
	if err != nil {
		Fatal("Unable to create TLS config", "error", err)
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{Timeout: time.Second * 30, Transport: transport}

	if "file" == cfg.Get("tls.pkey_source") {
		if handler := NewEciesLocalHandler(tlsCfg.Certificates[0].PrivateKey); handler != nil {
			return client, handler
		}
		Fatal("Unsupported private key")
	}
	return client, NewEciesPkcs11Handler(extra, tlsCfg.Certificates[0].PrivateKey)
}

func NewApp(configPaths []string, secretsDir string, unsafeHandlers, testing bool) (*App, error) {
	if len(configPaths) == 0 {
		configPaths = sotatoml.DEF_CONFIG_ORDER
	}
	sota, err := sotatoml.NewAppConfig(configPaths)
	if err != nil {
		return nil, fmt.Errorf("unable to parse sota.toml: %w", err)
	}
	return NewAppWithConfig(sota, secretsDir, unsafeHandlers, testing)
}

func NewAppWithConfig(sota *sotatoml.AppConfig, secretsDir string, unsafeHandlers, testing bool) (*App, error) {
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
		SecretsDir:      secretsDir,
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
	return true, sotatoml.SafeWrite(secretFile, newContent)
}

func (a *App) extract(config configSnapshot) (bool, error) {
	configChanged := false
	st, err := os.Stat(a.SecretsDir)
	if err != nil {
		return configChanged, err
	}

	all_fname := make(map[string]bool)
	for fname, cfgFile := range config.next {
		slog.Info("Extracting file", "file", fname)
		all_fname[fname] = true
		fullpath := filepath.Join(a.SecretsDir, fname)
		dirName := filepath.Dir(fullpath)
		if err := os.MkdirAll(dirName, st.Mode()); err != nil {
			return configChanged, fmt.Errorf("Unable to create parent directory secret: %s - %w", fullpath, err)
		}
		changed, err := updateSecret(fullpath, []byte(cfgFile.Value))
		if err != nil {
			return configChanged, err
		}
		if changed {
			configChanged = true
			a.runOnChanged(fname, fullpath, cfgFile.OnChanged)
		}
	}

	// Now, watch for file removals (compare with a previous version if present)
	if config.prev == nil {
		return configChanged, nil
	}
	for fname, cfgFile := range config.prev {
		if _, ok := all_fname[fname]; ok {
			continue
		}
		slog.Info("Removing file", "file", fname)
		configChanged = true
		fullpath := filepath.Join(a.SecretsDir, fname)
		if err := os.Remove(fullpath); err != nil && !os.IsNotExist(err) {
			return configChanged, err
		}
		a.runOnChanged(fname, fullpath, cfgFile.OnChanged)
	}
	if err := DeleteEmptyDirs(a.SecretsDir); err != nil {
		slog.Error("Unable to remove empty directories", "error", err)
	}
	return configChanged, nil
}

func (a *App) Extract() (bool, error) {
	_, crypto := createClient(a.sota)
	defer crypto.Close()

	config, err := UnmarshallFile(crypto, a.EncryptedConfig, true)
	if err != nil {
		return false, err
	}
	return a.extract(configSnapshot{nil, config})
}

func (a *App) runOnChanged(fname string, fullpath string, onChanged []string) {
	path, err := os.Readlink("/proc/self/exe")
	if err != nil {
		slog.Error("Unable to find path to self via /proc/self/exe", "error", err)
	}
	if len(onChanged) > 0 {
		binary := filepath.Clean(onChanged[0])
		if a.unsafeHandlers || strings.HasPrefix(binary, HandlersDir) {
			slog.Info("Running on-change command", "file", fname, "args", onChanged)
			cmd := exec.Command(onChanged[0], onChanged[1:]...)
			cmd.Env = append(os.Environ(), "CONFIG_FILE="+fullpath)
			cmd.Env = append(cmd.Env, "STORAGE_DIR="+a.StorageDir)
			cmd.Env = append(cmd.Env, "SOTA_DIR="+strings.Join(a.sota.SearchPaths(), ","))
			cmd.Env = append(cmd.Env, "FIOCONFIG_BIN="+path)

			if err := ExecIndented(cmd, "| "); err != nil {
				slog.Error("Unable to run command", "command", onChanged, "error", err)
				if exitError, ok := err.(*exec.ExitError); ok {
					if exitError.ExitCode() == onChangedForceExit {
						a.exitFunc(onChangedForceExit)
					}
				}
			}
		} else {
			slog.Warn("Skipping unsafe on-change command", "file", fname, "args", onChanged)
		}
	}
}

func (a *App) checkin(client *http.Client, crypto CryptoHandler) (configChanged bool, err error) {
	headers := make(map[string]string)
	var config configSnapshot

	if config.prev, err = UnmarshallFile(nil, a.EncryptedConfig, false); err != nil {
		var perr *os.PathError
		if !errors.As(err, &perr) || !os.IsNotExist(perr) {
			slog.Error("Unable to load previous config version", "error", err)
		}
	} else if fi, err := os.Stat(a.EncryptedConfig); err == nil {
		// Don't pull it down unless we need to
		ts := fi.ModTime().UTC().Format(time.RFC1123)
		headers["If-Modified-Since"] = ts
	}

	var res *transport.HttpRes
	res, err = transport.HttpGet(client, a.configUrl, headers)
	if err != nil {
		return // Unable to attempt request
	}

	if res.StatusCode == 200 {
		if config.next, err = UnmarshallBuffer(crypto, res.Body, true); err != nil {
			return
		}

		if configChanged, err = a.extract(config); err != nil {
			return
		}
		if err = sotatoml.SafeWrite(a.EncryptedConfig, res.Body); err != nil {
			return
		}

		modtime, err2 := time.Parse(time.RFC1123, res.Header.Get("Date"))
		if err2 != nil {
			slog.Warn("Unable to get modtime of config file, defaulting to 'now'", "error", err2)
			modtime = time.Now()
		}
		if err = os.Chtimes(a.EncryptedConfig, modtime, modtime); err != nil {
			err = fmt.Errorf("Unable to set modified time %s - %w", a.EncryptedConfig, err)
			return
		}
		return
	} else if res.StatusCode == 304 {
		slog.Info("Config on server has not changed")
		err = NotModifiedError
		return
	} else if res.StatusCode == 204 {
		slog.Info("Device has no config defined on server")
		err = NotModifiedError
		return
	}
	err = fmt.Errorf("Unable to get %s - HTTP_%d: %s", a.configUrl, res.StatusCode, res.String())
	return
}

func (a *App) CheckIn() (bool, error) {
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

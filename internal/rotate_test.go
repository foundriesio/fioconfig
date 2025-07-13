package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/foundriesio/fioconfig/sotatoml"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

type testStep struct {
	name      string
	execError error
}

func (t testStep) Name() string {
	return t.name
}

func (t testStep) Execute(_ *certRotationContext) error {
	return t.execError
}

type testClient struct {
	srv    *httptest.Server
	client *http.Client
}

func WithEstServer(t *testing.T, testFunc func(tc testClient)) {
	kp, err := tls.X509KeyPair([]byte(client_pem), []byte(pkey_pem))
	require.Nil(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A dumb server that just returns the same cert back to the requestor
		w.Header().Add("content-type", "application/pkcs7-mime")
		w.WriteHeader(201)
		bytes, err := pkcs7.DegenerateCertificate(kp.Certificate[0])
		require.Nil(t, err)
		bytes = []byte(base64.StdEncoding.EncodeToString(bytes))
		_, err = w.Write(bytes)
		require.Nil(t, err)
	}))

	srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := srv.Client()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.Certificates = []tls.Certificate{kp}

	tc := testClient{
		srv:    srv,
		client: client,
	}

	testFunc(tc)
}

func TestRotationHandler(t *testing.T) {
	testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
		stateFile := filepath.Join(tmpdir, "rotate.state")
		handler := NewCertRotationHandler(app, stateFile, "est-server-doesn't-matter")
		handler.eventSync = NoOpEventSync{}
		handler.cienv = true

		handler.steps = []certRotationStep{
			testStep{"step1", nil},
		}

		require.Nil(t, handler.Rotate())

		_, err := os.Stat(stateFile + ".completed")
		require.Nil(t, err)

		// Do one that fails, it should leave a statefile so we know where
		// we got to
		handler.State.StepIdx = 0
		handler.steps = []certRotationStep{
			testStep{"step1", errors.New("1")},
		}
		require.NotNil(t, handler.Rotate())
		handler = RestoreCertRotationHandler(app, stateFile)
		handler.cienv = true
		require.NotNil(t, handler)
		require.Equal(t, "est-server-doesn't-matter", handler.State.EstServer)

		// Check that we can resume from a non-zero StepIdx
		handler.steps = []certRotationStep{
			testStep{"step1", errors.New("Step 0 shouldn't have been run")},
			testStep{"step2", nil},
		}
		handler.State.StepIdx = 1
		require.Nil(t, handler.Rotate())
		require.Equal(t, 2, handler.State.StepIdx)
	})
}

func TestEst(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
			stateFile := filepath.Join(tmpdir, "rotate.state")
			handler := NewCertRotationHandler(app, stateFile, tc.srv.URL+"/.well-known/est")

			step := estStep{}

			require.Nil(t, step.Execute(&handler.stateContext))
			require.True(t, len(handler.State.NewCert) > 0)
			require.True(t, len(handler.State.NewKey) > 0)
		})
	})
}

func TestRotateFullConfig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.Nil(t, err)
	keyBytes = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
		stateFile := filepath.Join(tmpdir, "rotate.state")
		handler := NewCertRotationHandler(app, stateFile, "est-server-doesn't-matter")
		handler.State.NewKey = string(keyBytes)

		step := fullCfgStep{}

		require.Nil(t, step.Execute(&handler.stateContext))
		require.True(t, len(handler.State.FullConfigEncrypted) > 0)

		var config map[string]*ConfigFile
		require.Nil(t, json.Unmarshal([]byte(handler.State.FullConfigEncrypted), &config))
		require.Equal(t, "bar file value", config["bar"].Value)
		require.NotEqual(t, "foo file value", config["foo"].Value)

		c := NewEciesLocalHandler(key)
		config, err = UnmarshallBuffer(c, []byte(handler.State.FullConfigEncrypted), true)
		require.Nil(t, err)
		require.Equal(t, "foo file value", config["foo"].Value)
	})
}

func TestRotateLock(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.Nil(t, err)
	keyBytes = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	pubDer, err := x509.MarshalPKIXPublicKey(key.Public())
	require.Nil(t, err)
	pubBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	require.Nil(t, err)

	called := false

	dgHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			data, err := io.ReadAll(r.Body)
			require.Nil(t, err)
			var du DeviceUpdate
			require.Nil(t, json.Unmarshal(data, &du))

			require.Equal(t, string(pubBytes), du.NextPubKey)
			called = true
			return
		}
		http.NotFound(w, r)
	})

	testWrapper(t, dgHandler, func(app *App, client *http.Client, tmpdir string) {
		app.configUrl += "/"
		stateFile := filepath.Join(tmpdir, "rotate.state")
		handler := NewCertRotationHandler(app, stateFile, "est-server-doesn't-matter")
		handler.State.NewKey = string(keyBytes)

		step := lockStep{}

		require.Nil(t, step.Execute(&handler.stateContext))
		require.True(t, called)
	})
}

func TestRotateDeviceConfig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.Nil(t, err)
	keyBytes = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	pubDer, err := x509.MarshalPKIXPublicKey(key.Public())
	require.Nil(t, err)
	pubBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	require.Nil(t, err)

	var encbuf []byte
	var newcfg []byte

	dgHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, err := w.Write(encbuf)
			require.Nil(t, err)
			return
		} else if r.Method == "PATCH" {
			data, err := io.ReadAll(r.Body)
			require.Nil(t, err)
			var ccr ConfigCreateRequest
			require.Nil(t, json.Unmarshal(data, &ccr))
			cfg := make(ConfigStruct, len(ccr.Files))
			for _, file := range ccr.Files {
				cfg[file.Name] = &ConfigFile{
					Value:       file.Value,
					OnChanged:   file.OnChanged,
					Unencrypted: file.Unencrypted,
				}
			}
			newcfg, err = json.Marshal(cfg)
			require.Nil(t, err)
			require.Equal(t, string(pubBytes), ccr.PubKey)
			return
		}
		http.NotFound(w, r)
	})

	testWrapper(t, dgHandler, func(app *App, client *http.Client, tmpdir string) {
		app.configUrl += "/"
		encbuf, err = os.ReadFile(app.EncryptedConfig)
		require.Nil(t, err)
		stateFile := filepath.Join(tmpdir, "rotate.state")
		handler := NewCertRotationHandler(app, stateFile, "est-server-doesn't-matter")
		handler.State.NewKey = string(keyBytes)

		step := deviceCfgStep{}

		require.Nil(t, step.Execute(&handler.stateContext))
		require.True(t, handler.State.DeviceConfigUpdated)

		var config map[string]*ConfigFile
		require.Nil(t, json.Unmarshal(newcfg, &config))
		require.Equal(t, "bar file value", config["bar"].Value)
		require.NotEqual(t, "foo file value", config["foo"].Value)

		c := NewEciesLocalHandler(key)
		config, err = UnmarshallBuffer(c, newcfg, true)
		require.Nil(t, err)
		require.Equal(t, "foo file value", config["foo"].Value)

		// Now try our "resume" edge case. In this case we uploaded the new
		// encrypted config, but we weren't able to save the state to disk.
		// We have logic to recover from this (decrypt the config with the new
		// new key and update the local state)
		encbuf = newcfg
		newcfg = nil
		handler.State.DeviceConfigUpdated = false
		require.Nil(t, step.Execute(&handler.stateContext))
		require.Nil(t, newcfg) // We shouldn't have called PATCH /config-device
	})
}

func TestRotateFinalize(t *testing.T) {
	testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
		keyvals := map[string]string{
			"storage.path": tmpdir,
		}
		require.Nil(t, app.sota.UpdateKeys(keyvals))

		stateFile := filepath.Join(tmpdir, "rotate.state")
		handler := NewCertRotationHandler(app, stateFile, "est-server-doesn't-matter")
		handler.State.NewKey = "newkey"
		handler.State.NewCert = "newcert"

		step := finalizeStep{}
		require.Nil(t, step.Execute(&handler.stateContext))

		sota, err := sotatoml.NewAppConfig([]string{filepath.Join(tmpdir, "sota.toml")})
		require.Nil(t, err)

		bytes, err := os.ReadFile(sota.GetOrDie("import.tls_pkey_path"))
		require.Nil(t, err)
		require.Equal(t, "newkey", string(bytes))

		bytes, err = os.ReadFile(sota.GetOrDie("import.tls_clientcert_path"))
		require.Nil(t, err)
		require.Equal(t, "newcert", string(bytes))

		_, err = os.ReadFile(filepath.Join(tmpdir, "config.encrypted"))
		require.Nil(t, err)
	})
}

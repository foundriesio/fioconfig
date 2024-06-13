package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func WithEstServer(t *testing.T, doGet http.HandlerFunc, testFunc func(estServerUrl string)) {
	srv := httptest.NewUnstartedServer(doGet)
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	testFunc(srv.URL + "/.well-known/est")
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
	kp, err := tls.X509KeyPair([]byte(client_pem), []byte(pkey_pem))
	require.Nil(t, err)
	certDer := kp.Certificate[0]
	keyDer, err := x509.MarshalECPrivateKey(kp.PrivateKey.(*ecdsa.PrivateKey))
	require.Nil(t, err)
	bytes, err := pkcs7.DegenerateCertificate(certDer)
	require.Nil(t, err)
	bytes = []byte(base64.StdEncoding.EncodeToString(bytes))

	doGet := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A dumb server that just returns the same cert back to the requestor
		require.Equal(t, "/.well-known/est/simplereenroll", r.URL.Path)
		require.Equal(t, 1, len(r.TLS.PeerCertificates))
		require.Equal(t, certDer, r.TLS.PeerCertificates[0].Raw)
		w.Header().Add("content-type", "application/pkcs7-mime")
		w.WriteHeader(201)
		_, err = w.Write(bytes)
		require.Nil(t, err)
	})

	testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
		WithEstServer(t, doGet, func(estServerUrl string) {
			stateFile := filepath.Join(tmpdir, "rotate.state")
			handler := NewCertRotationHandler(app, stateFile, estServerUrl)

			step := estStep{}

			require.Nil(t, step.Execute(&handler.stateContext))
			// A dumb server returns the same cert, but estStep must generate a new key
			require.True(t, len(handler.State.NewCert) > 0)
			require.True(t, len(handler.State.NewKey) > 0)
			block, _ := pem.Decode([]byte(handler.State.NewCert))
			require.Equal(t, certDer, block.Bytes)
			block, _ = pem.Decode([]byte(handler.State.NewKey))
			require.NotEqual(t, keyDer, block.Bytes)
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
		require.Nil(t, app.sota.updateKeys(keyvals))

		stateFile := filepath.Join(tmpdir, "rotate.state")
		handler := NewCertRotationHandler(app, stateFile, "est-server-doesn't-matter")
		handler.State.NewKey = "newkey"
		handler.State.NewCert = "newcert"

		step := finalizeStep{}
		require.Nil(t, step.Execute(&handler.stateContext))

		sota, err := NewAppConfig([]string{filepath.Join(tmpdir, "sota.toml")})
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

func TestRenewRoot(t *testing.T) {
	doGet := func(caList ...*x509.Certificate) http.HandlerFunc {
		envelope, err := pkcs7.NewSignedData(nil)
		require.Nil(t, err)
		for _, cert := range caList {
			envelope.AddCertificate(cert)
		}
		bytes, err := envelope.Finish()
		require.Nil(t, err)
		bytes = []byte(base64.StdEncoding.EncodeToString(bytes))

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A dumb server that just returns the same cert back to the requestor
			require.Equal(t, "/.well-known/est/cacerts", r.URL.Path)
			w.Header().Add("content-type", "application/pkcs7-mime")
			w.WriteHeader(200)
			_, err = w.Write(bytes)
			require.Nil(t, err)
		})
	}

	testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
		handler := func(estServerUrl string) *RootRenewalHandler {
			stateFile := filepath.Join(tmpdir, "renew.state")
			h := NewRootRenewalHandler(app, stateFile, estServerUrl)
			h.cienv = true
			h.eventSync = NoOpEventSync{}
			return h
		}
		// Load initial CA cert and key
		bytes, err := os.ReadFile(filepath.Join(tmpdir, "root.crt"))
		require.Nil(t, err)
		block, _ := pem.Decode(bytes)
		initialCa, err := x509.ParseCertificate(block.Bytes)
		require.Nil(t, err)
		bytes, err = os.ReadFile(filepath.Join(tmpdir, "root.key"))
		require.Nil(t, err)
		initialKey, err := x509.ParsePKCS8PrivateKey(bytes)
		require.Nil(t, err)
		initialKeyRsa := initialKey.(*rsa.PrivateKey) // Golang test keys are RSA
		// Use a common CA template for all happy path tests
		newCaTmpl := &x509.Certificate{
			SerialNumber:          initialCa.SerialNumber,
			Subject:               initialCa.Subject,
			NotAfter:              time.Now().AddDate(1, 0, 0),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		var ii big.Int
		one := big.NewInt(1)
		// Generate the same CA with a different validity period
		newCaTmpl.SerialNumber = ii.Add(newCaTmpl.SerialNumber, one)
		newCaBytes, err := x509.CreateCertificate(
			rand.Reader, newCaTmpl, newCaTmpl, &initialKeyRsa.PublicKey, initialKeyRsa)
		require.Nil(t, err)
		sameCa, err := x509.ParseCertificate(newCaBytes)
		require.Nil(t, err)
		// Generate a new self-signed CA with a different key
		newCaTmpl.SerialNumber = ii.Add(newCaTmpl.SerialNumber, one)
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.Nil(t, err)
		newCaBytes, err = x509.CreateCertificate(
			rand.Reader, newCaTmpl, newCaTmpl, &newKey.PublicKey, newKey)
		require.Nil(t, err)
		newCa, err := x509.ParseCertificate(newCaBytes)
		require.Nil(t, err)
		// Generate a new CA with the same key as above which is cross-signed by the initial CA
		newCaTmpl.SerialNumber = ii.Add(newCaTmpl.SerialNumber, one)
		newCaBytes, err = x509.CreateCertificate(
			rand.Reader, newCaTmpl, initialCa, &newKey.PublicKey, initialKeyRsa)
		require.Nil(t, err)
		newCaCrossSigned, err := x509.ParseCertificate(newCaBytes)
		require.Nil(t, err)
		// Generate a new cert which is not a CA cert
		newCaTmpl.SerialNumber = ii.Add(newCaTmpl.SerialNumber, one)
		newCaTmpl.IsCA = false
		newCaBytes, err = x509.CreateCertificate(
			rand.Reader, newCaTmpl, initialCa, &initialKeyRsa.PublicKey, initialKeyRsa)
		require.Nil(t, err)
		nonCa, err := x509.ParseCertificate(newCaBytes)
		require.Nil(t, err)
		// Generate a new CA which a different subject and the same key as existing CA
		newCaTmpl.SerialNumber = ii.Add(newCaTmpl.SerialNumber, one)
		newCaTmpl.IsCA = true
		newCaTmpl.Subject = pkix.Name{CommonName: "test"}
		newCaBytes, err = x509.CreateCertificate(
			rand.Reader, newCaTmpl, initialCa, &initialKeyRsa.PublicKey, initialKeyRsa)
		require.Nil(t, err)
		diffCa, err := x509.ParseCertificate(newCaBytes)
		require.Nil(t, err)

		// Fail when EST server returns no cacerts
		WithEstServer(t, doGet(), func(estServerUrl string) {
			h := handler(estServerUrl)
			err := h.Update()
			require.NotNil(t, err)
			require.Equal(t, "Invalid pkcs7 data in EST response: no certificates", err.Error())
		})

		// Fail when EST server returns a non-CA cert
		WithEstServer(t, doGet(initialCa, nonCa), func(estServerUrl string) {
			h := handler(estServerUrl)
			err := h.Update()
			require.NotNil(t, err)
			require.Equal(t, "Error validating root certificates: Certificate with serial "+
				nonCa.SerialNumber.String()+" is not a certificate authority",
				err.Error())
		})

		// Fail when EST server returns a CA cert with a different subject
		WithEstServer(t, doGet(initialCa, diffCa), func(estServerUrl string) {
			h := handler(estServerUrl)
			err := h.Update()
			require.NotNil(t, err)
			require.Equal(t, "Error validating root certificates: "+
				"Unexpected subject 'CN=test' in certificate with serial "+
				diffCa.SerialNumber.String()+", must be 'O=Acme Co'",
				err.Error())
		})

		// Fail when EST server returns a new CA which is not signed by existing CA
		WithEstServer(t, doGet(newCa), func(estServerUrl string) {
			h := handler(estServerUrl)
			err := h.Update()
			require.NotNil(t, err)
			require.Equal(t, "Error validating root certificates: Certificate with serial "+
				newCa.SerialNumber.String()+" is neither (1) signed by one of current CAs "+
				"nor (2) has the same public key as another certificate which is signed by one of current CAs",
				err.Error())
		})

		// Succeed when EST server returns the same root CA as locally stored
		WithEstServer(t, doGet(initialCa), func(estServerUrl string) {
			h := handler(estServerUrl)
			require.Nil(t, h.Update())
		})

		// [Extension] Succeed when EST server returns a new root CA with the same key
		WithEstServer(t, doGet(sameCa), func(estServerUrl string) {
			h := handler(estServerUrl)
			require.Nil(t, h.Update())
		})

		// [Replacement phase 1] Succeed when EST server returns cacerts with 3 certs:
		// - the first is the same as the current CA;
		// - the second is signed by the current CA;
		// - the third is self-signed and has the same public key as the second one.
		WithEstServer(t, doGet(initialCa, newCaCrossSigned, newCa), func(estServerUrl string) {
			h := handler(estServerUrl)
			require.Nil(t, h.Update())
		})

		// Important: This must be the last test, as it stops accepting the test server TLS cert.
		// [Replacement phase 2] Succeed when EST server returns a subset of current CA certs.
		WithEstServer(t, doGet(newCa), func(estServerUrl string) {
			h := handler(estServerUrl)
			require.Nil(t, h.Update())
		})
	})
}

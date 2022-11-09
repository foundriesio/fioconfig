package internal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

const pub_pem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENGSaBHES7xdq8daCW2yfivX1Y2VE
fSpO4ImUGIA/IXd2VlPb0fNW+3kTKucNFsvW5k6fZxItC2KqJ28ffFiruQ==
-----END PUBLIC KEY-----`

const pkey_pem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfk24YU2ArBZ99NMX
wO4+BmzTKzjbEGQwiVSJhqUIq1ahRANCAAQ0ZJoEcRLvF2rx1oJbbJ+K9fVjZUR9
Kk7giZQYgD8hd3ZWU9vR81b7eRMq5w0Wy9bmTp9nEi0LYqonbx98WKu5
-----END PRIVATE KEY-----`

const client_pem = `
-----BEGIN CERTIFICATE-----
MIIBgjCCASmgAwIBAgIRAJjpxA3hJU0jqfFeQkV+bgcwCgYIKoZIzj0EAwIwGTEX
MBUGA1UEAwwOb3RhLWRldmljZXMtQ0EwHhcNMjAwNjE3MTg0MjA3WhcNNDAwNjEy
MTg0MjA3WjBBMRAwDgYDVQQLDAdkZWZhdWx0MS0wKwYDVQQDDCQ5OGU5YzQwZC1l
MTI1LTRkMjMtYTlmMS01ZTQyNDU3ZTZlMDcwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAQ0ZJoEcRLvF2rx1oJbbJ+K9fVjZUR9Kk7giZQYgD8hd3ZWU9vR81b7eRMq
5w0Wy9bmTp9nEi0LYqonbx98WKu5oyowKDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
AQH/BAwwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDRwAwRAIgPD6QZGSr1svchGAW
Jz2r/9CP9uby6JEzSrq2B0zkBewCIEKwxI/9j44n2NB8fzMOKbxAwKkI1sNTQRoJ
LSzKq+SZ
-----END CERTIFICATE-----
`

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
		if !cfgFile.Unencrypted {
			enc, err := ecies.Encrypt(rand.Reader, eciesPub, []byte(cfgFile.Value), nil, nil)
			if err != nil {
				t.Fatalf("Unable to encrypt %s: %s", fname, err)
			}
			cfgFile.Value = base64.StdEncoding.EncodeToString(enc)
		}
	}
}

func testWrapper(t *testing.T, doGet http.HandlerFunc, testFunc func(app *App, client *http.Client, tempdir string)) {
	dir := t.TempDir()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if doGet != nil {
			doGet(w, r)
		}
	}))
	defer ts.Close()

	certOut, err := os.Create(filepath.Join(dir, "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ts.TLS.Certificates[0].Certificate[0]}); err != nil {
		t.Fatal(err)
	}
	certOut.Close()
	if err := os.WriteFile(filepath.Join(dir, "pkey.pem"), []byte(pkey_pem), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.pem"), []byte(client_pem), 0644); err != nil {
		t.Fatal(err)
	}
	sota := fmt.Sprintf(`
[tls]
server = "%s"
ca_source = "file"
pkey_source = "file"
cert_source = "file"

[import]
tls_cacert_path = "%s/root.crt"
tls_pkey_path = "%s/pkey.pem"
tls_clientcert_path = "%s/client.pem"

[storage]
path = "%s"
	`, ts.URL, dir, dir, dir, dir)
	if err := os.WriteFile(filepath.Join(dir, "sota.toml"), []byte(sota), 0644); err != nil {
		t.Fatal(err)
	}

	config := make(map[string]*ConfigFile)
	config["foo"] = &ConfigFile{Value: "foo file value"}
	config["bar"] = &ConfigFile{
		Value:       "bar file value",
		OnChanged:   []string{"/usr/bin/touch", filepath.Join(dir, "bar-changed")},
		Unencrypted: true,
	}
	random := make([]byte, 1024) // 1MB random file
	_, err = rand.Read(random)
	if err != nil {
		t.Fatalf("Unable to create random buffer: %v", err)
	}
	config["random"] = &ConfigFile{Value: base64.StdEncoding.EncodeToString(random)}
	config["with/subdir/1.txt"] = &ConfigFile{Value: "sub"}

	encrypt(t, config)
	if config["foo"].Value == "foo file value" {
		t.Fatal("Encryption did not occur")
	}
	if config["bar"].Value != "bar file value" {
		t.Fatal("Encryption of bar should not have occurred")
	}
	app, err := NewApp(dir, dir, true, true)
	app.configUrl = ts.URL
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.EncryptedConfig, b, 0644); err != nil {
		t.Fatal(err)
	}
	testFunc(app, ts.Client(), dir)
}

func TestUnmarshall(t *testing.T) {
	testWrapper(t, nil, func(app *App, client *http.Client, tempdir string) {
		_, crypto := createClient(app.sota)
		defer crypto.Close()
		unmarshalled, err := UnmarshallFile(crypto, app.EncryptedConfig, true)
		if err != nil {
			t.Fatal(err)
		}
		if string(unmarshalled["foo"].Value) != "foo file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if string(unmarshalled["bar"].Value) != "bar file value" {
			t.Fatalf("Unable to unmarshal 'foo'")
		}
		if len(unmarshalled["random"].Value) != 1368 {
			t.Fatal("Invalid random unmarshalling")
		}
	})
}

func assertFile(t *testing.T, path string, contents []byte) {
	buff, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if contents != nil && !bytes.Equal(buff, contents) {
		t.Fatalf("Unexpected contents: %s != %s", contents, buff)
	}
}

func assertNoFile(t *testing.T, path string) {
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	} else {
		t.Fatalf("Unexpected file exists: %s", path)
	}
}

func TestExtract(t *testing.T) {
	testWrapper(t, nil, func(app *App, client *http.Client, tempdir string) {
		if err := app.Extract(); err != nil {
			t.Fatal(err)
		}

		assertFile(t, filepath.Join(tempdir, "foo"), []byte("foo file value"))
		assertFile(t, filepath.Join(tempdir, "bar"), []byte("bar file value"))
		assertFile(t, filepath.Join(tempdir, "random"), nil)
		barChanged := filepath.Join(tempdir, "bar-changed")
		assertFile(t, barChanged, nil)
		assertFile(t, filepath.Join(tempdir, "with/subdir/1.txt"), []byte("sub"))

		// Make sure files that don't change aren't updated
		os.Remove(barChanged)
		if err := app.Extract(); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(barChanged)
		if !os.IsNotExist(err) {
			t.Fatal("OnChanged called when file has not changed")
		}
	})
}

func TestSafeHandler(t *testing.T) {
	testWrapper(t, nil, func(app *App, client *http.Client, tempdir string) {
		app.unsafeHandlers = false
		if err := app.Extract(); err != nil {
			t.Fatal(err)
		}
		barChanged := filepath.Join(tempdir, "bar-changed")
		_, err := os.Stat(barChanged)
		if err == nil {
			t.Fatal("OnChanged called with safe handlers enabled")
		}
	})
}

func TestCheckBad(t *testing.T) {
	doGet := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	testWrapper(t, doGet, func(app *App, client *http.Client, tempdir string) {
		_, crypto := createClient(app.sota)
		defer crypto.Close()
		err := app.checkin(client, crypto)
		if err == nil {
			t.Fatal("Checkin should have gotten a 404")
		}

		if !strings.HasSuffix(strings.TrimSpace(err.Error()), "HTTP_404: 404 page not found") {
			t.Fatalf("Unexpected response: '%s'", err)
		}
	})
}

func TestCheckGood(t *testing.T) {
	var encbuf []byte
	var err error
	var removeBar bool

	doGet := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrtbuf := encbuf
		if removeBar {
			var wrtcfg map[string]*ConfigFile
			if err := json.Unmarshal(encbuf, &wrtcfg); err != nil {
				t.Fatal(err)
			}
			delete(wrtcfg, "bar")
			delete(wrtcfg, "with/subdir/1.txt")
			wrtbuf, err = json.Marshal(wrtcfg)
			if err != nil {
				t.Fatal(err)
			}
		} else if len(r.Header.Get("If-Modified-Since")) > 0 {
			w.WriteHeader(304)
			return
		}
		if _, err := w.Write(wrtbuf); err != nil {
			t.Fatal(err)
		}
	})

	testWrapper(t, doGet, func(app *App, client *http.Client, tempdir string) {
		_, crypto := createClient(app.sota)
		encbuf, err = os.ReadFile(app.EncryptedConfig)
		if err != nil {
			t.Fatal(err)
		}
		// Remove this file so we can be sure the check-in creates it
		os.Remove(app.EncryptedConfig)

		if err := app.checkin(client, crypto); err != nil {
			t.Fatal(err)
		}

		foo := filepath.Join(tempdir, "foo")
		bar := filepath.Join(tempdir, "bar")
		subdir := filepath.Join(tempdir, "with/subdir/1.txt")
		random := filepath.Join(tempdir, "random")
		barChanged := filepath.Join(tempdir, "bar-changed")

		// Make sure encrypted file exists
		assertFile(t, app.EncryptedConfig, nil)

		// Make sure decrypted files exist
		assertFile(t, foo, []byte("foo file value"))
		assertFile(t, bar, []byte("bar file value"))
		assertFile(t, subdir, nil)
		assertFile(t, random, nil)
		assertFile(t, barChanged, nil)
		barChangedStat, err := os.Stat(barChanged)
		if err != nil {
			t.Fatal(err)
		}
		barChangedTime := barChangedStat.ModTime()

		// modtime has a microsecond precision, but tests are so fast that even this is not enough
		time.Sleep(1 * time.Millisecond)

		// Now make sure the if-not-modified logic works
		if err := app.checkin(client, crypto); err != NotModifiedError {
			t.Fatal(err)
		}

		// Check that files removed on server are also removed on device and onChange is called
		removeBar = true
		if err := app.checkin(client, crypto); err != nil {
			t.Fatal(err)
		}

		// Make sure encrypted and backup files exist
		assertFile(t, app.EncryptedConfig, nil)

		// Make sure decrypted files exist
		assertFile(t, foo, []byte("foo file value"))
		assertNoFile(t, bar)
		assertNoFile(t, subdir)
		assertNoFile(t, "with")
		assertFile(t, random, nil)
		if barChangedStat, err := os.Stat(barChanged); err != nil {
			t.Fatal(err)
		} else if barChangedTime == barChangedStat.ModTime() {
			t.Fatalf("A barChanged modstamp is ought to change")
		}
	})
}

func TestInitFunctions(t *testing.T) {
	called := false
	initFunctions["OkComputer"] = func(app *App, client *http.Client, crypto CryptoHandler) error {
		called = true
		return nil
	}
	testWrapper(t, nil, func(app *App, client *http.Client, tempdir string) {
		app.CallInitFunctions()
	})
	if !called {
		t.Fatal("init function not called")
	}
	if len(initFunctions) != 0 {
		t.Fatal("initFunctions not cleared")
	}
}

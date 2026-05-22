package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/foundriesio/fioconfig/sotatoml"
)

func TestImportPath(t *testing.T) {
	dir := t.TempDir()
	// Build an AppConfig that sets import.base_path. The Get() lookups
	// require a real toml file behind the scenes.
	tomlPath := filepath.Join(dir, "sota.toml")
	if err := os.WriteFile(tomlPath, []byte(`
[import]
base_path           = "/var/sota/import"
tls_clientcert_path = "client.pem"
tls_pkey_path       = "pkey.pem"
tls_cacert_path     = "/abs/root.crt"
empty               = ""
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := sotatoml.NewAppConfig([]string{tomlPath})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key  string
		want string
	}{
		// relative -> joined onto base_path
		{"import.tls_clientcert_path", "/var/sota/import/client.pem"},
		{"import.tls_pkey_path", "/var/sota/import/pkey.pem"},
		// absolute -> passed through verbatim
		{"import.tls_cacert_path", "/abs/root.crt"},
		// empty -> empty
		{"import.empty", ""},
		// missing key -> empty (Get returns "" on miss)
		{"import.does_not_exist", ""},
	}
	for _, c := range cases {
		if got := importPath(cfg, c.key); got != c.want {
			t.Errorf("importPath(%q) = %q, want %q", c.key, got, c.want)
		}
	}

	// No base_path set: relative paths pass through unchanged.
	tomlNoBase := filepath.Join(dir, "no-base.toml")
	if err := os.WriteFile(tomlNoBase, []byte(`
[import]
tls_clientcert_path = "client.pem"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg2, err := sotatoml.NewAppConfig([]string{tomlNoBase})
	if err != nil {
		t.Fatal(err)
	}
	if got := importPath(cfg2, "import.tls_clientcert_path"); got != "client.pem" {
		t.Errorf("relative without base = %q, want %q", got, "client.pem")
	}
}

// TestGetTlsConfig_RelativeImportPaths exercises the full TLS bootstrap
// with the realistic relative-path layout that lmp-device-register +
// the aktualizr clients use. Without the importPath fix in tls.go,
// GetTlsConfig fails because os.ReadFile / tls.LoadX509KeyPair
// resolve the bare filename against the process CWD.
func TestGetTlsConfig_RelativeImportPaths(t *testing.T) {
	dir := t.TempDir()
	importDir := filepath.Join(dir, "import")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatal(err)
	}

	caPEM, err := mintSelfSigned(filepath.Join(importDir, "client.pem"), filepath.Join(importDir, "pkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(importDir, "root.crt"), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	tomlPath := filepath.Join(dir, "sota.toml")
	tomlBody := fmt.Sprintf(`
[tls]
ca_source   = "file"
pkey_source = "file"
cert_source = "file"

[import]
base_path           = "%s"
tls_clientcert_path = "client.pem"
tls_pkey_path       = "pkey.pem"
tls_cacert_path     = "root.crt"
`, importDir)
	if err := os.WriteFile(tomlPath, []byte(tomlBody), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := sotatoml.NewAppConfig([]string{tomlPath})
	if err != nil {
		t.Fatal(err)
	}

	// Run the test from a CWD that does NOT contain client.pem etc, to
	// prove the fix is what's making this work (not a stray file in
	// the process working dir).
	cwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	tlsCfg, _, err := GetTlsConfig(cfg)
	if err != nil {
		t.Fatalf("GetTlsConfig: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("certificates count = %d, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("RootCAs not populated from import.tls_cacert_path")
	}
}

// mintSelfSigned writes an ECDSA P-256 cert + PKCS#8 privkey to the
// given paths and returns the cert PEM (used as both the leaf and the
// CA in this test — the test only cares that GetTlsConfig succeeds at
// loading + parsing, not at chain validation).
func mintSelfSigned(certPath, keyPath string) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-device"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return certPEM, nil
}

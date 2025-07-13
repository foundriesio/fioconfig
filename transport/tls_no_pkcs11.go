//go:build disable_pkcs11

package transport

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/foundriesio/fioconfig/sotatoml"
)


func loadCertPkcs11(cfg *sotatoml.AppConfig) (*interface{}, tls.Certificate, error) {
	fmt.Println("ERROR: PKCS#11 is not supported")
	os.Exit(1)
	return nil, tls.Certificate{}, nil
}

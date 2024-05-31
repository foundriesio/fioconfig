package internal

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"
	"go.mozilla.org/pkcs7"
)

var (
	oidKeyUsage         = asn1.ObjectIdentifier([]int{2, 5, 29, 15})
	oidExtendedKeyUsage = asn1.ObjectIdentifier([]int{2, 5, 29, 37})

	asn1DigitalSignature = []byte{3, 2, 7, 128}
	asn1TlsWebClientAuth = []byte{48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2}
)

type estStep struct{}

func (s estStep) Name() string {
	return "Generate new certificate"
}

func (s estStep) Execute(handler *certRotationContext) error {
	// Find the current certificate so we can build the proper EST request
	tlsCert := handler.client.Transport.(*http.Transport).TLSClientConfig.Certificates[0]
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil
	}

	var signer crypto.Signer
	var newKey string

	// Generate a new private key
	if handler.usePkcs11() {
		newKey = s.nextPkeyId(handler)
		if err = handler.crypto.ctx.DeleteKeyPair(idToBytes(newKey), []byte("tls")); err != nil {
			return fmt.Errorf("Unable to free up slot(%s) for new keypair: %w", newKey, err)
		}
		pubAttr, err := crypto11.NewAttributeSetWithIDAndLabel(idToBytes(newKey), []byte("tls"))
		if err != nil {
			return fmt.Errorf("Unable to define pkcs11 attributes for new key: %w", err)
		}
		// The default ecdsa logic in crypto11 does not include the ability to
		// derive which is required for ECIES decryption
		pubAttr.AddIfNotPresent([]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true)})
		privAttr := pubAttr.Copy()
		signer, err = handler.crypto.ctx.GenerateECDSAKeyPairWithAttributes(pubAttr, privAttr, elliptic.P256())
		if err != nil {
			return fmt.Errorf("Unable to generate new keypair in HSM: %w", err)
		}
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("Unable to generate new private key: %w", err)
		}
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("Unable to serialize new private key: %w", err)
		}
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		newKey = string(keyBytes)
		signer = key
	}

	// Ask EST server for new cert
	csrBytes, err := createB64CsrDer(signer, cert)
	if err != nil {
		return err
	}

	url := handler.State.EstServer + "/simplereenroll"
	res, err := handler.client.Post(url, "application/pkcs10", bytes.NewBuffer(csrBytes))
	if err != nil {
		return fmt.Errorf("Unable to submit certificate signing request: %w", err)
	}
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("Unable to read certificate response body: HTTP_%d - %w", res.StatusCode, err)
	}
	if res.StatusCode != 201 {
		return fmt.Errorf("Unable to obtain new certificate: HTTP_%d - %s", res.StatusCode, string(buf))
	}
	ct := res.Header.Get("content-type")
	if ct != "application/pkcs7-mime" {
		return fmt.Errorf("Unexpected content-type return in certificate response: %s", ct)
	}
	estCert, err := decodeEstResponse(string(buf))
	if err != nil {
		return err
	}

	// Do minimal sanity checking on the new cert
	if err = verifyNewCert(cert, estCert); err != nil {
		return err
	}

	// Update our state
	if handler.usePkcs11() {
		newCert := s.nextCertId(handler)
		if err = handler.crypto.ctx.DeleteCertificate(idToBytes(newCert), nil, nil); err != nil {
			return fmt.Errorf("Unable to free up slot(%s) for new cert: %w", newCert, err)
		}
		if err = handler.crypto.ctx.ImportCertificateWithLabel(idToBytes(newCert), []byte("client"), estCert); err != nil {
			return fmt.Errorf("Unable to import new cert into HSM: %w", err)
		}
		handler.State.NewCert = newCert
	} else {
		handler.State.NewCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: estCert.Raw}))
	}

	handler.State.NewKey = newKey
	return nil
}

func (s estStep) nextPkeyId(handler *certRotationContext) string {
	cur := handler.app.sota.GetOrDie("p11.tls_pkey_id")
	for _, val := range handler.State.PkeySlotIds {
		if val != cur {
			return val
		}
	}
	log.Printf("ERROR: Unable to find a new key id. Will use slot 07")
	return "07"
}

func (s estStep) nextCertId(handler *certRotationContext) string {
	cur := handler.app.sota.GetOrDie("p11.tls_clientcert_id")
	for _, val := range handler.State.CertSlotIds {
		if val != cur {
			return val
		}
	}
	log.Printf("ERROR: Unable to find a new clientcert id. Will use slot 09")
	return "09"
}

// createB64CsrDer creates the payload for an EST simplereenroll payload. The
// main thing the EST server will want is for the x509 subject to be the same.
// Then we also need to ask for the proper x509 extensions.
func createB64CsrDer(key crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	template := x509.CertificateRequest{
		PublicKeyAlgorithm: 0,
		PublicKey:          key.Public(),
		RawSubject:         cert.RawSubject,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidKeyUsage,
				Critical: true,
				Value:    asn1DigitalSignature,
			},
			{
				Id:       oidExtendedKeyUsage,
				Critical: true,
				Value:    asn1TlsWebClientAuth,
			},
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(csrBytes)), nil
}

func decodeEstResponse(estResponse string) (*x509.Certificate, error) {
	bytes, err := base64.StdEncoding.DecodeString(estResponse)
	if err != nil {
		return nil, fmt.Errorf("Unable to base64 decode EST response: %w", err)
	}
	p7, err := pkcs7.Parse(bytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid pkcs7 data in EST response: %w", err)
	}
	return p7.Certificates[0], nil
}

func verifyNewCert(curCert, newCert *x509.Certificate) error {
	if !bytes.Equal(curCert.RawSubject, newCert.RawSubject) {
		return errors.New("New cert's subject does not match current cert's")
	}
	foundDigitalSig := false
	foundClientAuth := false
	for _, ext := range newCert.Extensions {
		if !foundDigitalSig && ext.Id.Equal(oidKeyUsage) {
			foundDigitalSig = bytes.Equal(ext.Value, asn1DigitalSignature)
		} else if !foundClientAuth && ext.Id.Equal(oidExtendedKeyUsage) {
			foundClientAuth = bytes.Equal(ext.Value, asn1TlsWebClientAuth)
		}
	}

	if foundDigitalSig && foundClientAuth {
		return nil
	}
	return errors.New("Missing required extensions for Digital Signature and/or TLS Web Client Authentication")
}

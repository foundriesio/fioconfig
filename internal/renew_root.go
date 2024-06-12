package internal

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

type RootRenewalState struct {
	BaseState
	EstServer string
}

type rootRenewalContext = stateContext[*RootRenewalState]
type rootRenewalStep = stateStep[*RootRenewalState]

// Not type RootRenewalHandler stateHandler[*RootRenewalState].
// We want methods from a parent to be inherited, thus use struct composition.
type RootRenewalHandler struct {
	stateHandler[*RootRenewalState]
}

func NewRootRenewalHandler(app *App, stateFile, estServer string) *RootRenewalHandler {
	state := &RootRenewalState{EstServer: estServer}
	return &RootRenewalHandler{
		stateHandler[*RootRenewalState]{
			stateContext: newStateContext[*RootRenewalState](app, stateFile, state),
			steps: []rootRenewalStep{
				fetchRootStep{},
			},
		},
	}
}

func RestoreRootRenewalHandler(app *App, stateFile string) *RootRenewalHandler {
	handler := NewRootRenewalHandler(app, stateFile, "")
	if ok := handler.Restore(); !ok {
		handler = nil
	}
	return handler
}

func (h *RootRenewalHandler) Update() error {
	return h.execute("RootCaUpdateStarted", "RootCaUpdateCompleted", true)
}

func (h *RootRenewalHandler) Resume(online bool) error {
	if !online {
		log.Print("Incomplete root CA renewal state found.")
		return nil
	}
	log.Print("Incomplete root CA renewal state found. Will attempt to complete")
	return h.Update()
}

type fetchRootStep struct{}

func (s fetchRootStep) Name() string {
	return "Fetch new root"
}

func (s fetchRootStep) Execute(h *rootRenewalContext) error {
	caFile := h.app.sota.GetOrDie("import.tls_cacert_path")
	caCertBuf, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal("Failed to read root CA file", err)
	}
	caCerts, err := loadCertsFromPem(caCertBuf)
	if err != nil {
		log.Fatal("Failed to parse root CA file", err)
	}

	url := h.State.EstServer + "/cacerts"
	res, err := h.client.Get(url)
	if err != nil {
		return fmt.Errorf("Unable to submit root certificate request: %w", err)
	}
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("Unable to read root certificate response body: HTTP_%d - %w", res.StatusCode, err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("Unable to obtain root certificate: HTTP_%d - %s", res.StatusCode, string(buf))
	}
	ct := res.Header.Get("content-type")
	if ct != "application/pkcs7-mime" {
		return fmt.Errorf("Unexpected content-type return in root certificate response: %s", ct)
	}
	certs, err := decodeEstResponse(string(buf))
	if err != nil {
		return err
	}

	if err = validateRootCerts(caCerts, certs, h.app.unsafeCaRenewal); err != nil {
		return fmt.Errorf("Error validating root certificates: %w", err)
	}

	var content bytes.Buffer
	for _, c := range certs {
		content.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if err = safeWrite(caFile, content.Bytes()); err != nil {
		return fmt.Errorf("Error updating root certificates file: %w", err)
	}
	return nil
}

func loadCertsFromPem(data []byte) (certs []*x509.Certificate, err error) {
	var block *pem.Block
	if len(data) == 0 {
		return nil, errors.New("Unexpected empty PEM block")
	}
	for len(data) > 0 {
		if block, data = pem.Decode(data); block == nil {
			return nil, fmt.Errorf("Malformed PEM block at %s", data[:100])
		} else if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Invalid PEM block type: %s", block.Type)
		} else if c, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("Invalid X.509 certificate: %w", err)
		} else {
			certs = append(certs, c)
		}
	}
	return
}

// As per crypto.PublicKey documentation, all public keys implement this interface.
type publicKey interface {
	Equal(x crypto.PublicKey) bool
}

func validateRootCerts(curCerts, newCerts []*x509.Certificate, skipSignatureCheck bool) error {
	// Each new certificate must pass all of the below checks:
	// 1. It is a valid certificate authority.
	// 2. Its subject is exactly the same as a subject of one of the current CAs.
	// 3. One of the following conditions is met:
	// 3.1. It is signed by one of the current CAs.
	// 3.2. It has the same public key as one of the current CAs.
	// 3.3. It has the same public key as any certificate satisfying 3.1.
	// Requirement 3 allows safely and securely rotating existing root CA in a 2-phase process:
	// - At first phase, the EST server returns 3 CAs:
	//   A. Current CA (self-signed or signed by a higher order CA);
	//   B. A new CA (self-signed or signed by a higher order CA);
	//   B1. A new CA with the same public key as the CA `B`, signed by a current CA.
	// - At second phase, the EST server returns only the CA `B` from the above.
	subj := curCerts[0].Subject.String() // All certs must have the same subject
	signedKeys := make([]publicKey, 1)
	skipKeyCheck := make([]bool, len(newCerts))
	for idx, cert := range newCerts {
		serial := cert.SerialNumber.String()
		if cert.Subject.String() != subj {
			return fmt.Errorf(
				"Unexpected subject '%s' in certificate with serial %s, must be '%s'",
				cert.Subject.String(), serial, subj,
			)
		} else if !cert.IsCA {
			return fmt.Errorf("Certificate with serial %s is not a certificate authority", serial)
		} else if !cert.BasicConstraintsValid {
			return fmt.Errorf("Certificate with serial %s failed basic constraints validation", serial)
		}
		// First loop identifies certificates matching condition 3.2.
		if skipSignatureCheck {
			skipKeyCheck[idx] = true
			continue
		}
		for _, ca := range curCerts {
			if cert.Equal(ca) {
				skipKeyCheck[idx] = true
				break
			} else if err := cert.CheckSignatureFrom(ca); err == nil {
				if pub, ok := cert.PublicKey.(publicKey); ok {
					signedKeys = append(signedKeys, pub)
				} else {
					// According to Golang docs this should be unreachable... keep here just for sanity.
					return fmt.Errorf(
						"Certificate with serial %s has invalid public key type: %T", serial, cert.PublicKey)
				}
				skipKeyCheck[idx] = true
				break
			}
		}
	}
	// Second loop identifies certificates matching condition 3.3.
	for idx, cert := range newCerts {
		if skipKeyCheck[idx] {
			continue
		}
		serial := cert.SerialNumber.String()
		if pub, ok := cert.PublicKey.(publicKey); ok {
			var isSigned bool
			for _, sigPub := range signedKeys {
				if isSigned = sigPub.Equal(pub); isSigned {
					break
				}
			}
			if !isSigned {
				return fmt.Errorf(
					"Certificate with serial %s is neither (1) signed by one of current CAs "+
						"nor (2) has the same public key as another certificate which is signed by one of current CAs",
					serial)
			}
		} else {
			// According to Golang docs this should be unreachable... keep here just for sanity.
			return fmt.Errorf(
				"Certificate with serial %s has invalid public key type: %T", serial, cert.PublicKey)
		}
	}
	return nil
}

package internal

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
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

func (h *RootRenewalHandler) Update() error {
	return h.execute("RootCaUpdateStarted", "RootCaUpdateCompleted", true)
}

type fetchRootStep struct{}

func (s fetchRootStep) Name() string {
	return "Fetch new root"
}

func (s fetchRootStep) Execute(h *rootRenewalContext) error {
	caFile := h.app.sota.GetOrDie("import.tls_cacert_path")
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

	var content bytes.Buffer
	for _, c := range certs {
		content.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if err = safeWrite(caFile, content.Bytes()); err != nil {
		return fmt.Errorf("Error updating root certificates file: %w", err)
	}
	return nil
}

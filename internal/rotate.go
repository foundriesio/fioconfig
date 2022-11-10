package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
)

type CertRotationState struct {
	EstServer   string
	RotationId  string // A unique ID to identify this rotation operation with
	StepIdx     int
	PkeySlotIds []string // Available IDs we can use when generating a new key
	CertSlotIds []string // Available IDs we can use when saving the new cert

	// Used by estStep
	NewKey  string // Path to key or HSM slot id
	NewCert string // Path to cert or HSM slot id

	// Used by fullCfgStep
	FullConfigEncrypted string

	// Used by deviceCfgStep
	DeviceConfigUpdated bool

	// Used by finalizeStep
	Finalized bool
}

type CertRotationHandler struct {
	State     CertRotationState
	stateFile string
	app       *App
	client    *http.Client
	crypto    *EciesCrypto
	steps     []CertRotationStep
}

type CertRotationStep interface {
	Name() string
	Execute(handler *CertRotationHandler) error
}

// NewCertRotationHandler constructs a new handler to initiate a rotation with
func NewCertRotationHandler(app *App, stateFile, estServer string) *CertRotationHandler {
	client, crypto := createClient(app.sota)
	return &CertRotationHandler{
		State:     CertRotationState{EstServer: estServer},
		stateFile: stateFile,
		app:       app,
		client:    client,
		crypto:    crypto.(*EciesCrypto),
		steps: []CertRotationStep{
			&estStep{},
			&lockStep{},
			&fullCfgStep{},
			&deviceCfgStep{},
			&finalizeStep{},
		},
	}
}

// RestoreCertRotationHandler will attempt to load a previous rotation attempt's
// state and return a handler that can process it. This function returns nil when
// `stateFile` does not exist
func RestoreCertRotationHandler(app *App, stateFile string) *CertRotationHandler {
	bytes, err := os.ReadFile(stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		} else {
			// Looks like we started a rotation, we should try and finish it
			log.Printf("Error reading %s, return empty rotation state: %s", stateFile, err)
		}
	}
	handler := NewCertRotationHandler(app, stateFile, "")
	if err = json.Unmarshal(bytes, &handler.State); err != nil {
		log.Printf("Error unmarshalling rotation state, return empty rotation state %s", err)
		return handler
	}
	return handler
}

func (h *CertRotationHandler) Save() error {
	bytes, err := json.Marshal(h.State)
	if err != nil {
		return err
	}
	return safeWrite(h.stateFile, bytes)
}

func (h *CertRotationHandler) Rotate() error {
	// Before we even start - we should save our initial state (ie EstServer)
	// and also make sure we *can* save our state.
	if err := h.Save(); err != nil {
		return fmt.Errorf("Unable to save initial state: %w", err)
	}
	for idx, step := range h.steps {
		if idx < h.State.StepIdx {
			log.Printf("Step already completed: %s", step.Name())
		} else {
			log.Printf("Executing step: %s", step.Name())
			if err := step.Execute(h); err != nil {
				return err
			}
			h.State.StepIdx += 1
			if saveErr := h.Save(); saveErr != nil {
				return fmt.Errorf("Unable to save state: %w", saveErr)
			}
		}
	}
	return os.Rename(h.stateFile, h.stateFile+".completed")
}

// ResumeRotation checks if we have an incomplete cert rotation. If so, it
// will attempt to complete this rotation. The main reason this would happen
// is if a power failure occurred during `.Rotate`
func (h *CertRotationHandler) ResumeRotation(online bool) error {
	if !online {
		// There's not much we can do because most rotation steps require
		// network access. However `fioconfig extract` runs at early boot and
		// needs help with one specific condition: the finalizeStep was able to
		// update sota.toml but didn't update config.encrypted. In this case
		// we can complete that one step locally and be good.
		if h.State.DeviceConfigUpdated && !h.State.Finalized {
			log.Print("Incomplete certificate rotation state found. Will attempt to complete")
			step := finalizeStep{}
			if err := step.Execute(h); err != nil {
				return err
			}
			// By calling save and not renaming the file .completed, `.Rotate`
			// will get called when online and we'll be able to emit a completion
			// event to the device gateway
			return h.Save()
		}
		log.Print("Incomplete certificate rotation state found.")
		return nil
	}
	log.Print("Incomplete certificate rotation state found. Will attempt to complete")
	return h.Rotate()
}

// useHsm detects if the handler should work with local files or PKCS11
func (h *CertRotationHandler) usePkcs11() bool {
	return h.crypto.ctx != nil
}

package internal

import (
	"log"
)

type CertRotationState struct {
	BaseState
	EstServer   string
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
	stateHandler
	State CertRotationState
}

type certRotationStep interface {
	Name() string
	Execute(handler *CertRotationHandler) error
}

func NewCertRotationHandler(app *App, stateFile, estServer string) *CertRotationHandler {
	handler := &CertRotationHandler{
		State:        CertRotationState{EstServer: estServer},
		stateHandler: newStateHandler(app, stateFile),
	}

	adapter := func(step certRotationStep) stateStep {
		return stateStep{
			Name: step.Name(),
			Execute: func(h *stateHandler) error {
				// Golang does not allow to convert stateHandler to CertRotationHandler
				// So, use closure to hold the reference to it.
				return step.Execute(handler)
			},
		}
	}

	handler.state = &handler.State
	handler.steps = []stateStep{
		adapter(estStep{}),
		adapter(lockStep{}),
		adapter(fullCfgStep{}),
		adapter(deviceCfgStep{}),
		adapter(finalizeStep{}),
	}
	return handler
}

// RestoreCertRotationHandler will attempt to load a previous rotation attempt's
// state and return a handler that can process it. This function returns nil when
// `stateFile` does not exist
func RestoreCertRotationHandler(app *App, stateFile string) *CertRotationHandler {
	handler := NewCertRotationHandler(app, stateFile, "")
	if ok := handler.Restore(); !ok {
		handler = nil
	}
	return handler
}

func (h *CertRotationHandler) Rotate() error {
	return h.execute("CertRotationStarted", "CertRotationCompleted", true)
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

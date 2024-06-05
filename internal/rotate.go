package internal

import (
	"log"
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

// NewCertRotationHandler constructs a new handler to initiate a rotation with
func NewCertRotationHandler(app *App, stateFile, estServer string) *CertRotationHandler {
	state := CertRotationState{EstServer: estServer}
	steps := []CertRotationStep{
		&estStep{},
		&lockStep{},
		&fullCfgStep{},
		&deviceCfgStep{},
		&finalizeStep{},
	}
	return newCertRotationHandler(app, stateFile, state, steps)
}

// RestoreCertRotationHandler will attempt to load a previous rotation attempt's
// state and return a handler that can process it. This function returns nil when
// `stateFile` does not exist
func RestoreCertRotationHandler(app *App, stateFile string) *CertRotationHandler {
	return restoreCertRotationHandler(app, stateFile)
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

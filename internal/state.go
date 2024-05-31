package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

type CertRotationHandler struct {
	State     CertRotationState
	stateFile string
	app       *App
	client    *http.Client
	crypto    *EciesCrypto
	eventSync EventSync
	steps     []CertRotationStep
	cienv     bool
}

type CertRotationStep interface {
	Name() string
	Execute(handler *CertRotationHandler) error
}

func newCertRotationHandler(
	app *App, stateFile string, state CertRotationState, steps []CertRotationStep,
) *CertRotationHandler {
	eventUrl := app.sota.GetOrDie("tls.server") + "/events"

	target, err := LoadCurrentTarget(filepath.Join(app.StorageDir, "current-target"))
	if err != nil {
		log.Printf("Unable to parse current-target. Events posted to server will be missing content: %s", err)
	}

	client, crypto := createClient(app.sota)
	return &CertRotationHandler{
		State:     state,
		stateFile: stateFile,
		app:       app,
		client:    client,
		crypto:    crypto.(*EciesCrypto),
		steps:     steps,
		eventSync: &DgEventSync{
			client: client,
			url:    eventUrl,
			target: target,
		},
	}
}

// usePkcs11 detects if the handler should work with local files or PKCS11
func (h *CertRotationHandler) usePkcs11() bool {
	return h.crypto.ctx != nil
}

func (h *CertRotationHandler) Save() error {
	bytes, err := json.Marshal(h.State)
	if err != nil {
		return err
	}
	return safeWrite(h.stateFile, bytes)
}

func restoreCertRotationHandler(app *App, stateFile string) *CertRotationHandler {
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

func (h *CertRotationHandler) execute() error {
	if len(h.State.RotationId) == 0 {
		h.State.RotationId = fmt.Sprintf("certs-%d", time.Now().Unix())
		log.Printf("Setting default rotation id to: %s", h.State.RotationId)
	}
	h.eventSync.SetCorrelationId(h.State.RotationId)
	var err error
	defer h.eventSync.NotifyCompleted(err)
	h.eventSync.NotifyStarted()

	// Before we even start - we should save our initial state (ie EstServer)
	// and also make sure we *can* save our state.
	if err = h.Save(); err != nil {
		return fmt.Errorf("Unable to save initial state: %w", err)
	}
	for idx, step := range h.steps {
		if idx < h.State.StepIdx {
			log.Printf("Step already completed: %s", step.Name())
		} else {
			log.Printf("Executing step: %s", step.Name())
			if err = step.Execute(h); err != nil {
				h.eventSync.NotifyStep(step.Name(), err)
				return err
			}
			h.State.StepIdx += 1
			h.eventSync.NotifyStep(step.Name(), nil)
			if err = h.Save(); err != nil {
				return fmt.Errorf("Unable to save state: %w", err)
			}
		}
	}
	err = os.Rename(h.stateFile, h.stateFile+".completed")

	// restart aklite and fioconfig *after* being "complete". Otherwise,
	// we could wind up in a loop of: try-to-complete-rotation,
	// restart-ourself-before marking complete
	h.RestartServices()

	return err
}

func (h *CertRotationHandler) RestartServices() {
	if h.cienv {
		fmt.Println("Skipping systemctl restarts for CI")
		return
	}

	ctx := context.Background()
	con, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		log.Fatalf("Unable to connect to DBUS for service restarts: %s", err)
	}

	for _, svc := range []string{"aktualizr-lite.service", "fioconfig.service"} {
		restartChan := make(chan string)
		_, err = con.RestartUnitContext(ctx, svc, "replace", restartChan)
		if err != nil {
			log.Fatalf("Unable to restart: %s, %s", svc, err)
		}
		result := <-restartChan
		switch result {
		case "done":
			continue
		default:
			log.Fatalf("Error restarting %s: %s", svc, result)
		}
	}
}

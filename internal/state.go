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

type BaseState struct {
	// A unique ID to identify this operation - RotationId inside a file for backward compatibility
	CorrelationId string `json:"RotationId"`
	StepIdx       int
}

type state interface {
	GetCorrelationId() string
	GetCurrentStep() int
	MoveToNextStep() int
}

func (s *BaseState) GetCorrelationId() string {
	if len(s.CorrelationId) == 0 {
		s.CorrelationId = fmt.Sprintf("certs-%d", time.Now().Unix())
		log.Printf("Setting default correlation id to: %s", s.CorrelationId)
	}
	return s.CorrelationId
}

func (s *BaseState) GetCurrentStep() int {
	return s.StepIdx
}

func (s *BaseState) MoveToNextStep() int {
	s.StepIdx += 1
	return s.StepIdx
}

type stateStep struct {
	Name    string
	Execute func(*stateHandler) error
}

type stateHandler struct {
	state     state
	stateFile string
	app       *App
	client    *http.Client
	crypto    *EciesCrypto
	eventSync EventSync
	steps     []stateStep
	cienv     bool
}

func newStateHandler(app *App, stateFile string) stateHandler {
	eventUrl := app.sota.GetOrDie("tls.server") + "/events"

	target, err := LoadCurrentTarget(filepath.Join(app.StorageDir, "current-target"))
	if err != nil {
		log.Printf("Unable to parse current-target. Events posted to server will be missing content: %s", err)
	}

	client, crypto := createClient(app.sota)
	return stateHandler{
		stateFile: stateFile,
		app:       app,
		client:    client,
		crypto:    crypto.(*EciesCrypto),
		eventSync: &DgEventSync{
			client: client,
			url:    eventUrl,
			target: target,
		},
	}
}

// usePkcs11 detects if the handler should work with local files or PKCS11
func (h *stateHandler) usePkcs11() bool {
	return h.crypto.ctx != nil
}

func (h *stateHandler) Save() error {
	bytes, err := json.Marshal(h.state)
	if err != nil {
		return err
	}
	return safeWrite(h.stateFile, bytes)
}

func (h *stateHandler) Restore() (loaded bool) {
	bytes, err := os.ReadFile(h.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		} else {
			// Looks like we started a rotation, we should try and finish it
			log.Printf("Error reading %s, return empty state: %s", h.stateFile, err)
		}
	}
	if err = json.Unmarshal(bytes, &h.state); err != nil {
		log.Printf("Error unmarshalling %s, return empty state %s", h.stateFile, err)
	}
	return true
}

func (h *stateHandler) execute(startEvent, completeEvent string, restart bool) error {
	h.eventSync.SetCorrelationId(h.state.GetCorrelationId())
	var err error
	defer h.eventSync.Notify(completeEvent, err)
	h.eventSync.Notify(startEvent, nil)

	// Before we even start - we should save our initial state (ie EstServer)
	// and also make sure we *can* save our state.
	if err = h.Save(); err != nil {
		return fmt.Errorf("Unable to save initial state: %w", err)
	}
	currentIdx := h.state.GetCurrentStep()
	for idx, step := range h.steps {
		if idx < currentIdx {
			log.Printf("Step already completed: %s", step.Name)
		} else {
			log.Printf("Executing step: %s", step.Name)
			if err = step.Execute(h); err != nil {
				h.eventSync.Notify(step.Name, err)
				return err
			}
			currentIdx = h.state.MoveToNextStep()
			h.eventSync.Notify(step.Name, nil)
			if err = h.Save(); err != nil {
				return fmt.Errorf("Unable to save state: %w", err)
			}
		}
	}
	err = os.Rename(h.stateFile, h.stateFile+".completed")

	if restart {
		// Restart aklite and fioconfig *after* being "complete".
		// Otherwise, we could wind up in a loop of:
		// try-to-complete-rotation, restart-ourself before marking complete.
		h.RestartServices()
	}

	return err
}

func (h *stateHandler) RestartServices() {
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

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
	"github.com/foundriesio/fioconfig/sotatoml"
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

type stateContext[T state] struct {
	State     T
	stateFile string
	app       *App
	client    *http.Client
	crypto    *EciesCrypto
	eventSync EventSync
	cienv     bool
}

type stateStep[T state] interface {
	Name() string
	Execute(*stateContext[T]) error
}

// stateContext type is needed to allow extending stateHandler subclasses with new facade methods
type stateHandler[T state] struct {
	stateContext[T]
	steps []stateStep[T]
}

func newStateContext[T state](app *App, stateFile string, state T) stateContext[T] {
	eventUrl := app.sota.GetOrDie("tls.server") + "/events"

	target, err := LoadCurrentTarget(filepath.Join(app.StorageDir, "current-target"))
	if err != nil {
		log.Printf("Unable to parse current-target. Events posted to server will be missing content: %s", err)
	}

	client, crypto := createClient(app.sota)
	return stateContext[T]{
		State:     state,
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
func (h stateContext[T]) usePkcs11() bool {
	return h.crypto.UsePkcs11()
}

func (h *stateContext[T]) Save() error {
	bytes, err := json.Marshal(h.State)
	if err != nil {
		return err
	}
	return sotatoml.SafeWrite(h.stateFile, bytes)
}

func (h *stateContext[T]) Restore() (loaded bool) {
	bytes, err := os.ReadFile(h.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		} else {
			// Looks like we started a rotation, we should try and finish it
			log.Printf("Error reading %s, return empty state: %s", h.stateFile, err)
		}
	}
	if err = json.Unmarshal(bytes, &h.State); err != nil {
		log.Printf("Error unmarshalling %s, return empty state %s", h.stateFile, err)
	}
	return true
}

func (h *stateHandler[T]) execute(startEvent, completeEvent string, restart bool) error {
	h.eventSync.SetCorrelationId(h.State.GetCorrelationId())
	var err error
	defer h.eventSync.Notify(completeEvent, err)
	h.eventSync.Notify(startEvent, nil)

	// Before we even start - we should save our initial state (ie EstServer)
	// and also make sure we *can* save our state.
	if err = h.Save(); err != nil {
		return fmt.Errorf("Unable to save initial state: %w", err)
	}
	currentIdx := h.State.GetCurrentStep()
	for idx, step := range h.steps {
		if idx < currentIdx {
			log.Printf("Step already completed: %s", step.Name())
		} else {
			log.Printf("Executing step: %s", step.Name())
			if err = step.Execute(&h.stateContext); err != nil {
				h.eventSync.Notify(step.Name(), err)
				return err
			}
			currentIdx = h.State.MoveToNextStep()
			h.eventSync.Notify(step.Name(), nil)
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

func (h *stateHandler[T]) RestartServices() {
	if h.cienv {
		fmt.Println("Skipping systemctl restarts for CI")
		return
	}

	ctx := context.Background()
	con, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		log.Fatalf("Unable to connect to DBUS for service restarts: %s", err)
	}
	services := []string{"aktualizr-lite.service", "fioconfig.service"}
	units, err := con.ListUnitsByNamesContext(ctx, []string{services[0]})
	if err != nil {
		log.Fatalf("Unable to query status of units: %s", err)
	}
	akliteSvc := units[0]
	for _, svc := range services {
		restartChan := make(chan string)
		if svc == akliteSvc.Name && (akliteSvc.ActiveState == "inactive" || akliteSvc.SubState == "dead") {
			continue
		}
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

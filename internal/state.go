package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/foundriesio/fioconfig/sotatoml"
	"golang.org/x/sys/unix"
)

var RotationInProgressError = errors.New("Another rotation is in progress")

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
		slog.Info("Setting default correlation id", "id", s.CorrelationId)
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
	restored  bool
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
		slog.Error("Unable to parse current-target. Events posted to server will be missing content", "error", err)
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
		if !errors.Is(err, os.ErrNotExist) {
			slog.Error("Unable to read state file", "file", h.stateFile, "error", err)
		}
		return false
	}
	if err = json.Unmarshal(bytes, &h.State); err != nil {
		// We can't tell how far this rotation got, so we don't resume it. The
		// file stays where it is. It could hold the only copy of a new private
		// key.
		slog.Error("Unable to unmarshall state file", "file", h.stateFile, "error", err)
		return false
	}
	h.restored = true
	return true
}

// lock stops other fioconfig processes from working on the state file while
// we do. The lock goes away with the file, so a crash can't leave it behind.
func (h *stateContext[T]) lock() (*os.File, error) {
	f, err := os.OpenFile(h.stateFile+".lock", os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return nil, fmt.Errorf("Unable to create lock file: %w", err)
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, RotationInProgressError
		}
		return nil, fmt.Errorf("Unable to lock %s: %w", f.Name(), err)
	}
	return f, nil
}

// checkNotClobbering makes sure a new operation doesn't throw away one that
// went further than its first step. After that the server may know about the
// new key, and the only copy of its private key can be in the state file.
func (h *stateContext[T]) checkNotClobbering() error {
	if h.restored {
		return nil
	}
	bytes, err := os.ReadFile(h.stateFile)
	if err != nil {
		return nil
	}
	var existing BaseState
	if err = json.Unmarshal(bytes, &existing); err != nil {
		return nil
	}
	if existing.StepIdx > 0 {
		return fmt.Errorf("%w: %s got to step %d", RotationInProgressError, existing.CorrelationId, existing.StepIdx)
	}
	return nil
}

func (h *stateHandler[T]) execute(startEvent, completeEvent string, restart bool) (err error) {
	lock, err := h.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = h.checkNotClobbering(); err != nil {
		return err
	}

	h.eventSync.SetCorrelationId(h.State.GetCorrelationId())
	h.eventSync.Notify(startEvent, nil)
	defer func() {
		h.eventSync.Notify(completeEvent, err)
		if restart && err == nil {
			// Restart aklite and fioconfig *after* being "complete".
			// Otherwise, we could wind up in a loop of:
			// try-to-complete-rotation, restart-ourself before marking complete.
			h.RestartServices()
		}
	}()

	// Before we even start - we should save our initial state (ie EstServer)
	// and also make sure we *can* save our state.
	if err = h.Save(); err != nil {
		return fmt.Errorf("Unable to save initial state: %w", err)
	}
	currentIdx := h.State.GetCurrentStep()
	for idx, step := range h.steps {
		if idx < currentIdx {
			slog.Info("Step already completed", "step", step.Name())
		} else {
			slog.Info("Executing step", "step", step.Name())
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
		Fatal("Unable to connect to DBUS for service restarts", "error", err)
	}
	services := []string{"aktualizr-lite.service", "fioconfig.service"}
	units, err := con.ListUnitsByNamesContext(ctx, []string{services[0]})
	if err != nil {
		Fatal("Unable to query status of units", "error", err)
	}
	akliteSvc := units[0]
	for _, svc := range services {
		restartChan := make(chan string)
		if svc == akliteSvc.Name && (akliteSvc.ActiveState == "inactive" || akliteSvc.SubState == "dead") {
			continue
		}
		_, err = con.RestartUnitContext(ctx, svc, "replace", restartChan)
		if err != nil {
			Fatal("Unable to restart service", "service", svc, "error", err)
		}
		result := <-restartChan
		switch result {
		case "done":
			continue
		default:
			Fatal("Error restarting service", "service", svc, "error", result)
		}
	}
}

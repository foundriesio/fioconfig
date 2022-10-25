package internal

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type testStep struct {
	name      string
	execError error
}

func (t testStep) Name() string {
	return t.name
}

func (t testStep) Execute(handler *CertRotationHandler) error {
	return t.execError
}

func TestRotationHandler(t *testing.T) {
	testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
		stateFile := filepath.Join(tmpdir, "rotate.state")
		handler := NewCertRotationHandler(app, stateFile, "est-server-doesn't-matter")

		handler.steps = []CertRotationStep{
			&testStep{"step1", nil},
		}

		require.Nil(t, handler.Rotate())

		_, err := os.Stat(stateFile + ".completed")
		require.Nil(t, err)

		// Do one that fails, it should leave a statefile so we know where
		// we got to
		handler.State.StepIdx = 0
		handler.steps = []CertRotationStep{
			&testStep{"step1", errors.New("1")},
		}
		require.NotNil(t, handler.Rotate())
		handler = RestoreCertRotationHandler(app, stateFile)
		require.NotNil(t, handler)
		require.Equal(t, "est-server-doesn't-matter", handler.State.EstServer)

		// Check that we can resume from a non-zero StepIdx
		handler.steps = []CertRotationStep{
			&testStep{"step1", errors.New("Step 0 shouldn't have been run")},
			&testStep{"step2", nil},
		}
		handler.State.StepIdx = 1
		require.Nil(t, handler.Rotate())
		require.Equal(t, 2, handler.State.StepIdx)
	})
}

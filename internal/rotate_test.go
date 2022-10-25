package internal

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
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

type testClient struct {
	srv    *httptest.Server
	client *http.Client
}

func WithEstServer(t *testing.T, testFunc func(tc testClient)) {
	kp, err := tls.X509KeyPair([]byte(client_pem), []byte(pkey_pem))
	require.Nil(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A dumb server that just returns the same cert back to the requestor
		w.Header().Add("content-type", "application/pkcs7-mime")
		w.WriteHeader(201)
		bytes, err := pkcs7.DegenerateCertificate(kp.Certificate[0])
		require.Nil(t, err)
		bytes = []byte(base64.StdEncoding.EncodeToString(bytes))
		_, err = w.Write(bytes)
		require.Nil(t, err)
	}))

	srv.TLS = &tls.Config{
		ClientAuth: tls.RequestClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := srv.Client()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.Certificates = []tls.Certificate{kp}

	tc := testClient{
		srv:    srv,
		client: client,
	}

	testFunc(tc)
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

func TestEst(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		testWrapper(t, nil, func(app *App, client *http.Client, tmpdir string) {
			stateFile := filepath.Join(tmpdir, "rotate.state")
			handler := NewCertRotationHandler(app, stateFile, tc.srv.URL+"/.well-known/est")

			step := estStep{}

			require.Nil(t, step.Execute(handler))
			require.True(t, len(handler.State.NewCert) > 0)
			require.True(t, len(handler.State.NewKey) > 0)
		})
	})
}

package internal

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type testFunc struct {
	called            int
	fakeOnCompleteErr bool
	includeFiles      bool
}

func (t testFunc) OnComplete(*App) {
	if !t.fakeOnCompleteErr {
		delete(initCallbacks, "test-func")
	}
}
func (t *testFunc) ConfigFiles(*App) []ConfigFileReq {
	t.called += 1
	if !t.includeFiles {
		return nil
	}
	file := ConfigFileReq{
		Name:        "name",
		Value:       "value",
		Unencrypted: true,
		OnChanged:   []string{},
	}
	return []ConfigFileReq{file}
}

func TestInitFuncs(t *testing.T) {
	errCode := 201
	fakeMethod := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(errCode)
	})

	// Just a basic test - no calls to a service
	initCallbacks["test-func"] = &testFunc{}
	testWrapper(t, nil, func(app *App, client *http.Client, tempdir string) {
		callInitFunctions(app, client)
	})
	require.Zero(t, len(initCallbacks))

	// Make sure we retry a function if it doesn't pass the first time
	tf := &testFunc{fakeOnCompleteErr: true}
	initCallbacks["test-func"] = tf
	testWrapper(t, nil, func(app *App, client *http.Client, tempdir string) {
		callInitFunctions(app, client)
		callInitFunctions(app, client)
	})
	require.Equal(t, 1, len(initCallbacks))
	require.Equal(t, 2, tf.called)

	// Make sure we handle a good server response
	tf = &testFunc{includeFiles: true}
	initCallbacks["test-func"] = tf
	testWrapper(t, fakeMethod, func(app *App, client *http.Client, tempdir string) {
		callInitFunctions(app, client)
		callInitFunctions(app, client)
	})
	require.Equal(t, 0, len(initCallbacks))
	require.Equal(t, 1, tf.called)

	// Make sure we handle a bad server response and retry
	errCode = 400
	tf = &testFunc{includeFiles: true}
	initCallbacks["test-func"] = tf
	testWrapper(t, fakeMethod, func(app *App, client *http.Client, tempdir string) {
		callInitFunctions(app, client)
		callInitFunctions(app, client)
	})
	require.Equal(t, 1, len(initCallbacks))
	require.Equal(t, 2, tf.called)
}

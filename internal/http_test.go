package internal

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHttpRetry(t *testing.T) {
	codes := []int{501, 200}
	idx := 0
	doGet := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(codes[idx])
		idx++
	})

	testWrapper(t, doGet, func(app *App, client *http.Client, tempdir string) {
		start := time.Now()
		res, err := httpGet(client, app.configUrl, nil)
		elapsed := time.Since(start)
		require.Nil(t, err)
		require.Equal(t, 200, res.StatusCode)
		require.Less(t, int64(1000), elapsed.Milliseconds())
		require.Equal(t, 2, idx)

		// Now do a test that won't retry:
		codes = []int{400}
		idx = 0
		res, err = httpGet(client, app.configUrl, nil)
		require.Nil(t, err)
		require.Equal(t, 400, res.StatusCode)
		require.Equal(t, 1, idx)
	})
}

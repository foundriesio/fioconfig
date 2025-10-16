package internal

import (
	"log/slog"
	"net/http"

	"github.com/foundriesio/fioconfig/transport"
)

type initCallback interface {
	ConfigFiles(a *App) []ConfigFileReq
	OnComplete(a *App)
}

var initCallbacks = map[string]initCallback{}

func callInitFunctions(a *App, client *http.Client) {
	ccr := ConfigCreateRequest{
		Reason: "Set initial fioconfig device data",
	}
	for name, cb := range initCallbacks {
		slog.Info("Running initialization", "callback", name)
		ccr.Files = append(ccr.Files, cb.ConfigFiles(a)...)
	}

	if len(ccr.Files) > 0 {
		res, err := transport.HttpPatch(client, a.configUrl, ccr)
		if err != nil {
			slog.Error("Unexpected error creating initialization request", "error", err)
		} else if res.StatusCode != 201 {
			slog.Error("Unable to update", "url", a.configUrl, "status", res.StatusCode, "response", string(res.Body))
			return
		}
	}

	for _, cb := range initCallbacks {
		cb.OnComplete(a)
	}
}

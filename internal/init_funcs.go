package internal

import (
	"log"
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
		log.Printf("Running %s initialization", name)
		ccr.Files = append(ccr.Files, cb.ConfigFiles(a)...)
	}

	if len(ccr.Files) > 0 {
		res, err := transport.HttpPatch(client, a.configUrl, ccr)
		if err != nil {
			log.Printf("Unexpected error creating initialization request: %s", err)
		} else if res.StatusCode != 201 {
			log.Printf("Unable to update: %s - HTTP_%d: %s", a.configUrl, res.StatusCode, string(res.Body))
			return
		}
	}

	for _, cb := range initCallbacks {
		cb.OnComplete(a)
	}
}

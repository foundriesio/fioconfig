package transport

import (
	"net/http"

	"log"
	"time"

	"github.com/foundriesio/fioconfig/sotatoml"
)

func CreateClient(cfg *sotatoml.AppConfig) (*http.Client) {
	tlsCfg, _, err := GetTlsConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &http.Client{Timeout: time.Second * 30, Transport: transport}
}

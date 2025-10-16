package internal

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/foundriesio/fioconfig/transport"
	"github.com/google/uuid"
)

// EventSync in an interface for sending events to device-gateway. The abstraction
// makes it easier to write unit tests
type EventSync interface {
	Notify(name string, err error)
	SetCorrelationId(corId string)
}

type NoOpEventSync struct{}

func (s NoOpEventSync) Notify(name string, err error) {}
func (s NoOpEventSync) SetCorrelationId(corId string) {}

type DgEventSync struct {
	client        *http.Client
	url           string
	correlationId string
	target        CurrentTarget
}

func (s *DgEventSync) SetCorrelationId(corId string) {
	s.correlationId = corId
}
func (s *DgEventSync) Notify(event string, err error) {
	details := ""
	if err != nil {
		details = err.Error()
	}
	evt := []DgUpdateEvent{
		{
			Id:         uuid.New().String(),
			DeviceTime: time.Now().Format(time.RFC3339),
			Event: DgEvent{
				CorrelationId: s.correlationId,
				Success:       err == nil,
				TargetName:    s.target.Name,
				Version:       strconv.Itoa(s.target.Version),
				Details:       details,
			},
			EventType: DgEventType{
				Id:      event,
				Version: 0,
			},
		},
	}
	res, err := transport.HttpPost(s.client, s.url, evt)
	if err != nil {
		slog.Error("Unable to send event", "error", err)
	} else if res.StatusCode < 200 || res.StatusCode > 204 {
		slog.Error("Server could not process event", "event", event, "status", res.StatusCode, "response", res.String())
	}
}

type DgEvent struct {
	CorrelationId string `json:"correlationId"`
	//Ecu           string `json:"ecu"`
	Success    bool   `json:"success"`
	TargetName string `json:"targetName"`
	Version    string `json:"version"`
	Details    string `json:"details,omitempty"`
}
type DgEventType struct {
	Id      string `json:"id"`
	Version int    `json:"version"`
}
type DgUpdateEvent struct {
	Id         string      `json:"id"`
	DeviceTime string      `json:"deviceTime"`
	Event      DgEvent     `json:"event"`
	EventType  DgEventType `json:"eventType"`
}

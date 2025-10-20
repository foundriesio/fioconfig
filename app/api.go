package app

import (
	"github.com/foundriesio/fioconfig/internal"
	"github.com/foundriesio/fioconfig/sotatoml"
)

type App internal.App

var NotModifiedError = internal.NotModifiedError

// NewAppWithConfig creates a new App instance with the provided SOTA configuration
// that can perform all the basic Fioconfig operations.
func NewAppWithConfig(sota *sotatoml.AppConfig, secretsDir string, unsafeHandlers bool) (*App, error) {
	app, err := internal.NewAppWithConfig(sota, secretsDir, unsafeHandlers, false)
	if err != nil {
		return nil, err
	}
	return (*App)(app), nil
}

// Extract extracts secrets from the encrypted configuration into the secrets directory.
// must be called once. A common way to do this is a systemd "oneshot" service after
// NetworkManager is up.
func (a *App) Extract() error {
	return (*internal.App)(a).Extract()
}

// CheckIn checks with the device gateway for the lastest configuration. If there
// are changes, it applies them locally. If the config on the server is unchanged,
// it returns NotModifiedError. This function also will try and run any pending
// "init" functions required by Fioconfig that have not yet been run.
func (a *App) CheckIn() error {
	return (*internal.App)(a).CheckIn()
}

// RunAndReport runs a command specified by name with args, and collects
// artifacts found under artifactsDir. It reports the results back to the
// device-gateway's fiotest API under the test identified by testId.
func (a *App) RunAndReport(name, testId, artifactsDir string, args []string) error {
	return (*internal.App)(a).RunAndReport(name, testId, artifactsDir, args)
}

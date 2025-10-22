package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/foundriesio/fioconfig/app"
	"github.com/foundriesio/fioconfig/internal"
	"github.com/foundriesio/fioconfig/sotatoml"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

func isTerminal(fd *os.File) bool {
	_, err := unix.IoctlGetTermios(int(fd.Fd()), unix.TCGETS)
	return err == nil
}

func NewApp(c *cli.Context) (*internal.App, error) {
	if isTerminal(os.Stderr) {
		orig := slog.NewTextHandler(os.Stderr, nil)
		handler := app.NewConsoleHandler(orig, os.Stdout, os.Stderr)
		logger := slog.New(handler)
		slog.SetDefault(logger)
	}

	app, err := internal.NewApp(c.StringSlice("config"), c.String("secrets-dir"), c.Bool("unsafe-handlers"), false)
	if err != nil {
		return nil, err
	}
	if c.Command.Name == "renew-cert" {
		return app, nil
	}
	stateFile := filepath.Join(app.StorageDir, "cert-rotation.state")
	handler := internal.RestoreCertRotationHandler(app, stateFile)
	if handler != nil {
		online := c.Command.Name != "extract"
		err = handler.ResumeRotation(online)
	}
	return app, err
}

func extract(c *cli.Context) error {
	app, err := NewApp(c)
	if err != nil {
		return err
	}

	if _, err := os.Stat(app.SecretsDir); os.IsNotExist(err) {
		slog.Info("Creating secrets directory", "dir", app.SecretsDir)
		if err := os.Mkdir(app.SecretsDir, 0750); err != nil {
			return err
		}
	}
	slog.Info("Extracting keys", "from", app.EncryptedConfig, "to", app.SecretsDir)
	if err := app.Extract(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("Encrypted config does not exist")
		} else {
			return err
		}
	}
	return nil
}

func checkin(c *cli.Context) error {
	app, err := NewApp(c)
	if err != nil {
		return err
	}

	slog.Info("Checking in with server ...")
	if err := app.CheckIn(); err != nil && !errors.Is(err, internal.NotModifiedError) {
		return err
	}
	return nil
}

func daemon(c *cli.Context) error {
	interval := time.Second * time.Duration(c.Int("interval"))
	app, err := NewApp(c)
	if err != nil {
		return err
	}
	slog.Info("Running as daemon", "interval", c.Int("interval"))
	for {
		slog.Info("Checking in with server")
		if err := app.CheckIn(); err != nil && !errors.Is(err, internal.NotModifiedError) {
			slog.Error("Check-in failed", "error", err)
		}
		time.Sleep(interval)
	}
}

func renewCert(c *cli.Context) error {
	app, err := NewApp(c)
	if err != nil {
		return err
	}
	if c.NArg() != 1 && c.NArg() != 2 {
		cli.ShowCommandHelpAndExit(c, "renew-cert", 1)
	}
	server := c.Args().Get(0)
	stateFile := filepath.Join(app.StorageDir, "cert-rotation.state")
	handler := internal.NewCertRotationHandler(app, stateFile, server)
	idsStr := c.String("pkcs11-key-ids")
	handler.State.PkeySlotIds = strings.Split(idsStr, ",")
	idsStr = c.String("pkcs11-cert-ids")
	handler.State.CertSlotIds = strings.Split(idsStr, ",")

	if c.NArg() == 2 {
		handler.State.CorrelationId = c.Args().Get(1)
	}

	slog.Info("Performing certificate renewal")
	if err = handler.Rotate(); err == nil {
		slog.Info("Certificate rotation sequence complete")
	}
	return err
}

func runAndReport(c *cli.Context) error {
	testId := c.String("id")
	testName := c.String("name")

	if len(testId) > 0 {
		pattern := `^[A-Za-z0-9\-\_]{15,48}$`
		if !regexp.MustCompile(pattern).MatchString(testId) {
			return fmt.Errorf("Invalid test ID: %s, must match pattern %s", testId, pattern)
		}
	}
	pattern := `^[a-z0-9\-\_]{4,16}$`
	if !regexp.MustCompile(pattern).MatchString(testName) {
		return fmt.Errorf("Invalid test ID: %s, must match pattern %s", testName, pattern)
	}

	app, err := NewApp(c)
	if err != nil {
		return err
	}
	if c.NArg() == 0 {
		cli.ShowCommandHelpAndExit(c, "run-and-report", 1)
	}

	args := c.Args().Slice()
	slog.Info("Running command", "args", args)
	return app.RunAndReport(testName, testId, c.String("artifacts-dir"), args)
}

func main() {
	app := &cli.App{
		Name:  "fioconfig",
		Usage: "A daemon to handle configuration management for devices in a Foundries Factory",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   cli.NewStringSlice(sotatoml.DEF_CONFIG_ORDER...),
				Usage:   "Aktualizr config paths",
				EnvVars: []string{"SOTA_DIR"},
			},
			&cli.StringFlag{
				Name:    "secrets-dir",
				Aliases: []string{"s"},
				Value:   "/var/run/secrets",
				Usage:   "Location to extract configuration to",
				EnvVars: []string{"SECRETS_DIR"},
			},
			&cli.BoolFlag{
				Name:    "unsafe-handlers",
				Usage:   "Enable running on-changed handlers defined outside of /usr/share/fioconfig/handlers/",
				EnvVars: []string{"UNSAFE_CALLBACKS"},
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "extract",
				Usage: "Extract the current encrypted configuration to secrets directory",
				Action: func(c *cli.Context) error {
					return extract(c)
				},
			},
			{
				Name:  "check-in",
				Usage: "Check in with the server and update the local config",
				Action: func(c *cli.Context) error {
					return checkin(c)
				},
			},
			{
				Name:  "daemon",
				Usage: "Run check-in's with the server in an endless loop",
				Action: func(c *cli.Context) error {
					return daemon(c)
				},
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "interval",
						Aliases: []string{"i"},
						Value:   300,
						Usage:   "Interval in seconds for checking in for updates",
						EnvVars: []string{"DAEMON_INTERVAL"},
					},
				},
			},
			{
				Name:     "renew-cert",
				HelpName: "renew-cert <EST Server> [<rotation-id>]",
				Usage:    "Renew device's TLS keypair used with device-gateway",
				Action: func(c *cli.Context) error {
					return renewCert(c)
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "pkcs11-key-ids",
						Value: "01,07",
						Usage: "The two pkcs11 slot IDs to use for private keys",
					},
					&cli.StringFlag{
						Name:  "pkcs11-cert-ids",
						Value: "03,09",
						Usage: "The two pkcs11 slot IDs to use for client certificates",
					},
				},
			},
			{
				Name:     "run-and-report",
				HelpName: "run-and-report <command...>",
				Usage:    "Run a command and report the output to the device-gateway",
				Action: func(c *cli.Context) error {
					return runAndReport(c)
				},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Required: true,
						Usage:    "A short name for the test",
					},
					&cli.StringFlag{
						Name:  "id",
						Usage: "UUID for the test",
					},
					&cli.StringFlag{
						Name:  "artifacts-dir",
						Usage: "Include files in this directory as artifacts in the test result",
					},
				},
			},
			{
				Name:  "version",
				Usage: "Display version of this command",
				Action: func(c *cli.Context) error {
					fmt.Println(internal.Commit)
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		internal.Fatal(err.Error())
	}
}

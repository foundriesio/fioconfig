package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/foundriesio/fioconfig/internal"
	"github.com/urfave/cli/v2"
)

func NewApp(c *cli.Context) (*internal.App, error) {
	app, err := internal.NewApp(c.String("config"), c.String("secrets-dir"), c.Bool("unsafe-handlers"), false)
	if err != nil {
		return nil, err
	}
	if c.Command.Name == "renew-cert" {
		return app, nil
	}
	stateFile := filepath.Join(c.String("config"), "cert-rotation.state")
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
		log.Printf("Creating secrets directory: %s", app.SecretsDir)
		if err := os.Mkdir(app.SecretsDir, 0750); err != nil {
			return err
		}
	}
	log.Printf("Extracting keys from %s to %s", app.EncryptedConfig, app.SecretsDir)
	if err := app.Extract(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println("Encrypted config does not exist")
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
	log.Print("Checking in with server")
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
	log.Printf("Running as daemon with interval %d seconds", c.Int("interval"))
	for {
		log.Print("Checking in with server")
		if err := app.CheckIn(); err != nil && !errors.Is(err, internal.NotModifiedError) {
			log.Println(err)
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
	stateFile := filepath.Join(c.String("config"), "cert-rotation.state")
	handler := internal.NewCertRotationHandler(app, stateFile, server)
	idsStr := c.String("pkcs11-key-ids")
	handler.State.PkeySlotIds = strings.Split(idsStr, ",")
	idsStr = c.String("pkcs11-cert-ids")
	handler.State.CertSlotIds = strings.Split(idsStr, ",")

	if c.NArg() == 2 {
		handler.State.RotationId = c.Args().Get(1)
	}

	log.Printf("Performing certificate renewal")
	if err = handler.Rotate(); err == nil {
		log.Print("Certificate rotation sequence complete")
	}
	return err
}

func main() {
	app := &cli.App{
		Name:  "fioconfig",
		Usage: "A daemon to handle configuration management for devices in a Foundries Factory",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "/var/sota",
				Usage:   "Aktualizr config directory",
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
		log.Fatal(err)
	}
}

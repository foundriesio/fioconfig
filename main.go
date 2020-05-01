package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/foundriesio/fioconfig/internal"
	"github.com/urfave/cli/v2"
)

func NewApp(c *cli.Context) (*internal.App, error) {
	return internal.NewApp(c.String("config"), c.String("secrets-dir"), false)
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

func main() {
	app := &cli.App{
		Name:  "fioconfig",
		Usage: "An approach to encrypted config management that would make Bruce Schneier cry",
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
				Name:  "version",
				Usage: "Dispaly version of this command",
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

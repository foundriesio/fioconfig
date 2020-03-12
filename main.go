package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/foundriesio/schneierteard/internal"
	"github.com/urfave/cli/v2"
)

func NewApp(c *cli.Context) (*internal.App, error) {
	return internal.NewApp(c.String("config"), c.String("secrets-dir"))
}

func extract(c *cli.Context) error {
	app, err := NewApp(c)
	if err != nil {
		return err
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
	return app.CheckIn()
}

func main() {
	app := &cli.App{
		Name:  "schneier-teard",
		Usage: "An approach to encrypted config management that would make Bruce cry",
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

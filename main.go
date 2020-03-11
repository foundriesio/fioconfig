package main

import (
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
	return nil
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
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

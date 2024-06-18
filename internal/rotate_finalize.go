package internal

import (
	"fmt"
	"os"
	"path/filepath"
)

type finalizeStep struct{}

func (s finalizeStep) Name() string {
	return "Finalize aktualizr configuration"
}

func (s finalizeStep) Execute(handler *certRotationContext) error {
	storagePath := handler.app.StorageDir
	keyvals := make(map[string]string)
	if handler.usePkcs11() {
		// Point at the new key ids
		keyvals["p11.tls_pkey_id"] = handler.State.NewKey
		keyvals["p11.tls_clientcert_id"] = handler.State.NewCert
	} else {
		// Write out two new files and update sota.toml
		// They need to be *new* unique names, so just use tempfile since it
		// includes the logic for uniqueness
		files := [][3]string{
			{"pkey.*.pem", "import.tls_pkey_path", handler.State.NewKey},
			{"client.*.pem", "import.tls_clientcert_path", handler.State.NewCert},
		}
		for _, pair := range files {
			f, err := os.CreateTemp(storagePath, pair[0])
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err = f.WriteString(pair[2]); err != nil {
				return err
			}
			if err = f.Sync(); err != nil {
				return err
			}
			keyvals[pair[1]] = f.Name()
		}
	}
	if err := handler.app.sota.updateKeys(keyvals); err != nil {
		return err
	}

	if len(handler.State.FullConfigEncrypted) > 0 {
		path := filepath.Join(storagePath, "config.encrypted")
		if err := safeWrite(path, []byte(handler.State.FullConfigEncrypted)); err != nil {
			return fmt.Errorf("Error updating config.encrypted: %w", err)
		}
	}
	handler.State.Finalized = true
	return nil
}

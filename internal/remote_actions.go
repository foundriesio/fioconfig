//go:build !disable_remoteactions

package internal

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type raInitCallback struct {
	newActions []byte
}

func (r *raInitCallback) ConfigFiles(app *App) []ConfigFileReq {
	const actionsDir = "/usr/share/fioconfig/actions"
	var actions []string
	entries, err := os.ReadDir(actionsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// This is a bug - we can't read the directory for some reason
		slog.Error("Unable to initialize remote actions", "error", err)
		return nil
	} else if err == nil {
		for _, entry := range entries {
			actions = append(actions, entry.Name())
		}
	}
	actionsStr := strings.Join(actions, ",")

	content, err := os.ReadFile(filepath.Join(app.SecretsDir, "fio-remote-actions"))
	if err != nil {
		if os.IsNotExist(err) {
			content = nil
		} else {
			slog.Warn("Unable to read configured remote actions", "error", err)
			return nil
		}
	}

	if !bytes.Equal(content, []byte(actionsStr)) {
		slog.Info("Configured remote actions changed", "old", string(content), "new", actionsStr)
		file := ConfigFileReq{
			Name:        "fio-remote-actions",
			Unencrypted: true,
			Value:       actionsStr,
		}
		r.newActions = []byte(actionsStr)
		return []ConfigFileReq{file}
	}

	// prevent init logic from calling OnComplete by removing ourselves
	delete(initCallbacks, "remote-actions")
	return nil
}

func (r raInitCallback) OnComplete(app *App) {
	delete(initCallbacks, "remote-actions")
}

func init() {
	initCallbacks["remote-actions"] = &raInitCallback{}
}

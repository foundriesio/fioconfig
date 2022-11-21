package internal

import (
	"errors"
	"strconv"

	"github.com/pelletier/go-toml"
)

type CurrentTarget struct {
	Name    string
	Version int
}

func LoadCurrentTarget(currentTargeFile string) (CurrentTarget, error) {
	var cur CurrentTarget
	ctToml, err := toml.LoadFile(currentTargeFile)
	if err != nil {
		return cur, err
	}
	if val, ok := ctToml.Get("TARGET_NAME").(string); !ok || len(val) == 0 {
		return cur, errors.New("Unable to parse current-target. No TARGET_NAME specified")
	} else {
		cur.Name = val
	}
	if val, ok := ctToml.Get("CUSTOM_VERSION").(string); !ok || len(val) == 0 {
		return cur, errors.New("Unable to parse current-target. No CUSTOM_VERSON specified")
	} else {
		cur.Version, err = strconv.Atoi(val)
		if err != nil {
			return cur, err
		}
	}
	return cur, nil
}

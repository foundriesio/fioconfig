package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadCurrentTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test-current-target")
	content := `
TARGET_NAME="intel-corei7-64-lmp-277"
CUSTOM_VERSION="277"
LMP_MANIFEST_SHA="afc74c3ecb0528238b08a40d8b576792cc11c202"
META_SUBSCRIBER_OVERRIDES_SHA="c1dfca8299829e9d1bf5d10174cf9fbcc788a9a8"
CONTAINERS_SHA="821478af94b8199114d5c8731bd53f17a5663ff8"
TAG="production"
	`
	require.Nil(t, os.WriteFile(path, []byte(content), 0o700))
	tgt, err := LoadCurrentTarget(path)
	require.Nil(t, err)
	require.Equal(t, "intel-corei7-64-lmp-277", tgt.Name)
	require.Equal(t, 277, tgt.Version)
}

func TestLoadCurrentTargetBadContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test-current-target")
	content := `
LINE_MISSING_EQUALS_CHAR
CUSTOM_VERSION="277"
LMP_MANIFEST_SHA="afc74c3ecb0528238b08a40d8b576792cc11c202"
META_SUBSCRIBER_OVERRIDES_SHA="c1dfca8299829e9d1bf5d10174cf9fbcc788a9a8"
CONTAINERS_SHA="821478af94b8199114d5c8731bd53f17a5663ff8"
TAG="production"
	`
	require.Nil(t, os.WriteFile(path, []byte(content), 0o700))
	_, err := LoadCurrentTarget(path)
	require.NotNil(t, err)
}

func TestLoadCurrentMissingRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test-current-target")
	content := `
#TARGET_NAME="intel-corei7-64-lmp-277"
CUSTOM_VERSION="277"
LMP_MANIFEST_SHA="afc74c3ecb0528238b08a40d8b576792cc11c202"
META_SUBSCRIBER_OVERRIDES_SHA="c1dfca8299829e9d1bf5d10174cf9fbcc788a9a8"
CONTAINERS_SHA="821478af94b8199114d5c8731bd53f17a5663ff8"
TAG="production"
	`
	require.Nil(t, os.WriteFile(path, []byte(content), 0o700))
	_, err := LoadCurrentTarget(path)
	require.NotNil(t, err)
}

func TestLoadCurrentBadVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test-current-target")
	content := `
#TARGET_NAME="intel-corei7-64-lmp-277"
CUSTOM_VERSION="NotANumber"
LMP_MANIFEST_SHA="afc74c3ecb0528238b08a40d8b576792cc11c202"
META_SUBSCRIBER_OVERRIDES_SHA="c1dfca8299829e9d1bf5d10174cf9fbcc788a9a8"
CONTAINERS_SHA="821478af94b8199114d5c8731bd53f17a5663ff8"
TAG="production"
	`
	require.Nil(t, os.WriteFile(path, []byte(content), 0o700))
	_, err := LoadCurrentTarget(path)
	require.NotNil(t, err)
}

package fiotest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecCommand(t *testing.T) {
	tr := ExecCommand([]string{"/bin/true", "abc"}, "")
	require.Equal(t, "PASSED", tr.Status)
	require.Equal(t, "/bin/true abc", tr.Details)

	require.Equal(t, 1, len(tr.Artifacts))
	require.Equal(t, []byte{}, tr.Artifacts.Get("console.log").Content())

	tr = ExecCommand([]string{"/bin/false"}, "")
	require.Equal(t, "FAILED", tr.Status)

	tr = ExecCommand([]string{"/bin/echo", "THIS IS A TEST!"}, "")
	require.Equal(t, "PASSED", tr.Status)
	require.Equal(t, "THIS IS A TEST!\n", string(tr.Artifacts.Get("console.log").Content()))
}

func TestExecCommandArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "run.sh")

	content := `#!/bin/sh -e
echo TEST OUTPUT
echo ARTIFACT OUTPUT > ${ARTIFACTS}/test.txt`
	require.Nil(t, os.WriteFile(path, []byte(content), 0o755))

	tr := ExecCommand([]string{path}, t.TempDir())
	require.Equal(t, "PASSED", tr.Status)
	require.Equal(t, 2, len(tr.Artifacts))

	require.Equal(t, "ARTIFACT OUTPUT\n", string(tr.Artifacts.Get("test.txt").Content()))

	require.Equal(t, "TEST OUTPUT\n", string(tr.Artifacts.Get("console.log").Content()))
}

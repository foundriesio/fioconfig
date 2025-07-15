package fiotest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecCommand(t *testing.T) {
	tr := ExecCommand([]string{"/bin/true", "abc"})
	require.Equal(t, "PASSED", tr.Status)
	require.Equal(t, "/bin/true abc", tr.Details)

	require.Equal(t, 1, len(tr.Artifacts))
	require.Equal(t, []byte{}, tr.Artifacts.Get("console.log").Content())

	tr = ExecCommand([]string{"/bin/false"})
	require.Equal(t, "FAILED", tr.Status)

	tr = ExecCommand([]string{"/bin/echo", "THIS IS A TEST!"})
	require.Equal(t, "PASSED", tr.Status)
	require.Equal(t, "THIS IS A TEST!\n", string(tr.Artifacts.Get("console.log").Content()))
}

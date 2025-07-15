package fiotest

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type ResultArtifact interface {
	Name() string
	Content() []byte
}

type ResultArtifacts []ResultArtifact

func (a ResultArtifacts) Get(name string) ResultArtifact {
	for _, a := range a {
		if a.Name() == name {
			return a
		}
	}
	return nil
}

type Result struct {
	Status    string
	Details   string
	Artifacts ResultArtifacts
}

// ExecCommand will run the given command and wrap the results in a structure
// that aligns with what the device-gateway's fiotest API will expect.
func ExecCommand(args []string) Result {
	r := Result{
		Status:  "PASSED",
		Details: strings.Join(args, " "),
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		r.Status = "FAILED"
		if output != nil {
			output = fmt.Appendf(nil, "Unable to run command: %s", err)
		} else {
			errBytes := fmt.Appendf(nil, "\n----\nUnable to run command: %s", err)
			output = append(output, errBytes...)
		}
	}
	r.Artifacts = append(r.Artifacts, &consoleOutput{output})
	return r
}

type consoleOutput struct {
	output []byte
}

func (consoleOutput) Name() string {
	return "console.log"
}

func (c consoleOutput) Content() []byte {
	return c.output
}

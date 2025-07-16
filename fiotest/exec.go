package fiotest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
// that aligns with what the device-gateway's fiotest API will expect. If
// `artifactsDir` is set the command will be run with an environment variable
// `ARTIFACTS` set to that directory. The command can then save files in
// variable where test artifacts can be saved by the command and included
// in the test result.
func ExecCommand(args []string, artifactsDir string) Result {
	r := Result{
		Status:  "PASSED",
		Details: strings.Join(args, " "),
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	if len(artifactsDir) > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("ARTIFACTS=%s", artifactsDir))
	}
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

	if len(artifactsDir) > 0 {
		entries, err := os.ReadDir(artifactsDir)
		if err != nil {
			errBytes := fmt.Appendf(nil, "\n\nERROR: unable to find test artifacts: %s", err)
			output = append(output, errBytes...)
		} else {
			for _, entry := range entries {
				if entry.Type().IsRegular() {
					r.Artifacts = append(r.Artifacts, &fileOutput{path: artifactsDir, name: entry.Name()})
				}
			}
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

type fileOutput struct {
	path string
	name string
}

func (f fileOutput) Name() string {
	return f.name
}

func (f fileOutput) Content() []byte {
	buf, err := os.ReadFile(filepath.Join(f.path, f.name))
	if err != nil {
		buf = fmt.Appendf(nil, "\n\nERROR: unable to read trigger artifact: %s: %s", f.name, err)
	}
	return buf
}

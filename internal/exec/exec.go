package exec

import (
	"bytes"
	"os/exec"
)

// Run executes the named command with args and returns the combined stdout+stderr output.
func Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// LookPath checks whether a binary is available in the system PATH.
func LookPath(name string) error {
	_, err := exec.LookPath(name)
	return err
}

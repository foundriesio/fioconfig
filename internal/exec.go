package internal

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
)

func ExecIndented(cmd *exec.Cmd, indentChars string) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr: %w", err)
	}

	if err = cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go prefixAndCopy(indentChars, stdout, os.Stdout, &wg)
	go prefixAndCopy(indentChars, stderr, os.Stderr, &wg)

	wg.Wait()
	return cmd.Wait()
}

// prefixAndCopy reads from r line by line and writes to w with "| " prefix.
func prefixAndCopy(prefix string, r io.Reader, w io.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fmt.Fprint(w, prefix, scanner.Text(), "\n")
	}
	if err := scanner.Err(); err != nil {
		slog.Error("Error reading command output", "error", err)
	}
}

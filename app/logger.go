package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

const (
	colorRed   = "\033[31m"
	colorReset = "\033[0m"
)

type ConsoleHandler struct {
	mu      *sync.Mutex // guards writes to out
	stdout  io.Writer
	stderr  io.Writer
	handler slog.Handler
}

// NewConsoleHandler creates a slog handler targeted for CLI interfaces being
// run in an interactive mode with a TTY. The console handler:
//   - Passes slog.LevelDebug and slog.LevelWarning to the underlying handler
//     to work as usual
//   - Prints slog.LevelInfo messages to stdout in the most natural way it can
//   - Prints slog.LevelError messages to stderr with an `ERROR:` prefix in red.
//
// Its basically a way to try and turn an API that was designed for structured
// logging inside a daemon to be more usable in a CLI application.
func NewConsoleHandler(h slog.Handler, stdout, stderr io.Writer) slog.Handler {
	mu := &sync.Mutex{}
	return &ConsoleHandler{
		stdout:  stdout,
		stderr:  stderr,
		mu:      mu,
		handler: h,
	}
}

func (h *ConsoleHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *ConsoleHandler) Handle(ctx context.Context, r slog.Record) error {
	switch r.Level {
	case slog.LevelError:
		r.Message = fmt.Sprintf("%sERROR:%s %s", colorRed, colorReset, r.Message)
		return h.print(h.stderr, r)
	case slog.LevelInfo:
		return h.print(h.stdout, r)
	default:
		return h.handler.Handle(ctx, r)
	}
}

func (h *ConsoleHandler) print(w io.Writer, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	fmt.Fprint(w, r.Message)
	first := true
	r.Attrs(func(a slog.Attr) bool {
		if first {
			fmt.Fprintf(w, ": %s=%s", a.Key, a.Value)
			first = false
		} else {
			fmt.Fprintf(w, ", %s=%s", a.Key, a.Value)
		}
		return true
	})
	fmt.Fprint(w, "\n")
	return nil
}

func (h *ConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ConsoleHandler{
		stdout:  h.stdout,
		stderr:  h.stderr,
		mu:      h.mu,
		handler: h.handler.WithAttrs(attrs),
	}
}

func (h *ConsoleHandler) WithGroup(name string) slog.Handler {
	return &ConsoleHandler{
		stdout:  h.stdout,
		stderr:  h.stderr,
		mu:      h.mu,
		handler: h.handler.WithGroup(name),
	}
}

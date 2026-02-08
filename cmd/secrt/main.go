package main

import (
	"crypto/rand"
	"io"
	"net/http"
	"os"

	"golang.org/x/term"
)

func main() {
	deps := Deps{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		HTTPClient:  http.DefaultClient,
		IsTTY:       func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		IsStdoutTTY: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		Getenv:      os.Getenv,
		Rand:        rand.Reader,
		ReadPass: func(prompt string, w io.Writer) (string, error) {
			_, _ = io.WriteString(w, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			_, _ = io.WriteString(w, "\n")
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	}
	os.Exit(run(os.Args, deps))
}

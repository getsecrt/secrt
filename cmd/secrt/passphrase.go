package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// resolvePassphrase extracts a passphrase from flags using the provided Deps.
// Returns (passphrase, error). Empty passphrase means none requested.
func resolvePassphrase(args parsedArgs, deps Deps) (string, error) {
	count := 0
	if args.passphrasePrompt {
		count++
	}
	if args.passphraseEnv != "" {
		count++
	}
	if args.passphraseFile != "" {
		count++
	}
	if count > 1 {
		return "", fmt.Errorf("specify at most one of --passphrase-prompt, --passphrase-env, --passphrase-file")
	}
	if count == 0 {
		return "", nil
	}

	if args.passphraseEnv != "" {
		p := deps.Getenv(args.passphraseEnv)
		if p == "" {
			return "", fmt.Errorf("environment variable %q is empty or not set", args.passphraseEnv)
		}
		return p, nil
	}

	if args.passphraseFile != "" {
		data, err := os.ReadFile(args.passphraseFile)
		if err != nil {
			return "", fmt.Errorf("read passphrase file: %w", err)
		}
		p := strings.TrimRight(string(data), "\r\n")
		if p == "" {
			return "", fmt.Errorf("passphrase file is empty")
		}
		return p, nil
	}

	// Prompt
	if deps.ReadPass == nil {
		return "", fmt.Errorf("passphrase prompt not available")
	}

	p, err := deps.ReadPass("Passphrase: ", deps.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if p == "" {
		return "", fmt.Errorf("passphrase must not be empty")
	}

	return p, nil
}

// resolvePassphraseForCreate is like resolvePassphrase but prompts for confirmation.
func resolvePassphraseForCreate(args parsedArgs, deps Deps) (string, error) {
	// Check for conflicting flags first (before any I/O)
	count := 0
	if args.passphrasePrompt {
		count++
	}
	if args.passphraseEnv != "" {
		count++
	}
	if args.passphraseFile != "" {
		count++
	}
	if count > 1 {
		return "", fmt.Errorf("specify at most one of --passphrase-prompt, --passphrase-env, --passphrase-file")
	}

	if !args.passphrasePrompt {
		return resolvePassphrase(args, deps)
	}

	if deps.ReadPass == nil {
		return "", fmt.Errorf("passphrase prompt not available")
	}

	p1, err := deps.ReadPass("Passphrase: ", deps.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if p1 == "" {
		return "", fmt.Errorf("passphrase must not be empty")
	}

	p2, err := deps.ReadPass("Confirm passphrase: ", deps.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase confirmation: %w", err)
	}
	if p1 != p2 {
		return "", fmt.Errorf("passphrases do not match")
	}

	return p1, nil
}

func writeError(w io.Writer, jsonMode bool, msg string) {
	if jsonMode {
		fmt.Fprintf(w, `{"error":%q}`+"\n", msg)
	} else {
		fmt.Fprintf(w, "error: %s\n", msg)
	}
}

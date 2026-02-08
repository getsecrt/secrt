package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"secret/internal/envelope"
)

func runCreate(args []string, deps Deps) int {
	pa, err := parseFlags(args, nil)
	if err == errShowHelp {
		printCreateHelp(deps)
		return 0
	}
	if err != nil {
		writeError(deps.Stderr, pa.json, err.Error())
		return 2
	}
	resolveGlobals(&pa, deps)

	// Read plaintext from exactly one source
	plaintext, err := readPlaintext(pa, deps)
	if err != nil {
		writeError(deps.Stderr, pa.json, err.Error())
		return 2
	}

	// Parse TTL
	var ttlSeconds *int64
	if pa.ttl != "" {
		ttl, err := envelope.ParseTTL(pa.ttl)
		if err != nil {
			writeError(deps.Stderr, pa.json, fmt.Sprintf("invalid TTL: %v", err))
			return 2
		}
		ttlSeconds = &ttl
	}

	// Resolve passphrase
	passphrase, err := resolvePassphraseForCreate(pa, deps)
	if err != nil {
		writeError(deps.Stderr, pa.json, err.Error())
		return 2
	}

	// Seal envelope
	result, err := envelope.Seal(envelope.SealParams{
		Plaintext:  plaintext,
		Passphrase: passphrase,
		Rand:       deps.Rand,
	})
	if err != nil {
		writeError(deps.Stderr, pa.json, fmt.Sprintf("encryption failed: %v", err))
		return 1
	}

	// Upload to server
	client := &APIClient{
		BaseURL:    pa.baseURL,
		APIKey:     pa.apiKey,
		HTTPClient: deps.HTTPClient,
	}

	resp, err := client.Create(CreateRequest{
		Envelope:   result.Envelope,
		ClaimHash:  result.ClaimHash,
		TTLSeconds: ttlSeconds,
	})
	if err != nil {
		writeError(deps.Stderr, pa.json, err.Error())
		return 1
	}

	// Output
	shareLink := envelope.FormatShareLink(resp.ShareURL, result.URLKey)

	if pa.json {
		out := map[string]interface{}{
			"id":         resp.ID,
			"share_url":  resp.ShareURL,
			"share_link": shareLink,
			"expires_at": resp.ExpiresAt,
		}
		enc := json.NewEncoder(deps.Stdout)
		enc.Encode(out)
	} else {
		fmt.Fprintln(deps.Stdout, shareLink)
	}

	return 0
}

func readPlaintext(pa parsedArgs, deps Deps) ([]byte, error) {
	sources := 0
	if pa.text != "" {
		sources++
	}
	if pa.file != "" {
		sources++
	}

	if sources > 1 {
		return nil, fmt.Errorf("specify exactly one input source (stdin, --text, or --file)")
	}

	if pa.text != "" {
		if pa.text == "" {
			return nil, fmt.Errorf("--text value must not be empty")
		}
		return []byte(pa.text), nil
	}

	if pa.file != "" {
		data, err := os.ReadFile(pa.file)
		if err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("file is empty")
		}
		return data, nil
	}

	// stdin
	if deps.IsTTY() {
		fmt.Fprint(deps.Stderr, "Enter secret (Ctrl+D to finish):\n")
	}

	data, err := io.ReadAll(deps.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("input is empty")
	}
	return data, nil
}

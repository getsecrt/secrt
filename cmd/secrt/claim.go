package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"secret/internal/envelope"
)

func runClaim(args []string, deps Deps) int {
	pa, err := parseFlags(args, nil)
	if err == errShowHelp {
		printClaimHelp(deps)
		return 0
	}
	if err != nil {
		writeError(deps.Stderr, pa.json, err.Error())
		return 2
	}
	resolveGlobals(&pa, deps)

	if len(pa.args) < 1 {
		writeError(deps.Stderr, pa.json, "share URL is required")
		return 2
	}

	shareURL := pa.args[0]

	// Parse URL to extract ID and url_key
	id, urlKey, err := envelope.ParseShareURL(shareURL)
	if err != nil {
		writeError(deps.Stderr, pa.json, fmt.Sprintf("invalid share URL: %v", err))
		return 2
	}

	// Derive base URL from share URL if not explicitly set via flag/env
	baseURL := pa.baseURL
	if !pa.baseURLFromFlag && deps.Getenv("SECRET_BASE_URL") == "" {
		if u, err := url.Parse(shareURL); err == nil && u.Scheme != "" {
			baseURL = u.Scheme + "://" + u.Host
		}
	}

	// Derive claim token from url_key alone
	claimToken, err := envelope.DeriveClaimToken(urlKey)
	if err != nil {
		writeError(deps.Stderr, pa.json, fmt.Sprintf("key derivation failed: %v", err))
		return 1
	}

	// Claim from server
	client := &APIClient{
		BaseURL:    baseURL,
		APIKey:     pa.apiKey,
		HTTPClient: deps.HTTPClient,
	}

	resp, err := client.Claim(id, claimToken)
	if err != nil {
		writeError(deps.Stderr, pa.json, fmt.Sprintf("claim failed: %v", err))
		return 1
	}

	// Resolve passphrase for decryption
	passphrase, err := resolvePassphrase(pa, deps)
	if err != nil {
		writeError(deps.Stderr, pa.json, err.Error())
		return 1
	}

	// Decrypt envelope
	plaintext, err := envelope.Open(envelope.OpenParams{
		Envelope:   resp.Envelope,
		URLKey:     urlKey,
		Passphrase: passphrase,
	})
	if err != nil {
		writeError(deps.Stderr, pa.json, fmt.Sprintf("decryption failed: %v", err))
		return 1
	}

	// Output
	if pa.json {
		out := map[string]interface{}{
			"expires_at": resp.ExpiresAt,
		}
		enc := json.NewEncoder(deps.Stdout)
		enc.Encode(out)
	} else {
		deps.Stdout.Write(plaintext)
	}

	return 0
}

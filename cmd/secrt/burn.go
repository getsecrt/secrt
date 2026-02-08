package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"secret/internal/envelope"
)

func runBurn(args []string, deps Deps) int {
	pa, err := parseFlags(args, nil)
	if errors.Is(err, errShowHelp) {
		printBurnHelp(deps)
		return 0
	}
	if err != nil {
		writeError(deps.Stderr, pa.json, err.Error())
		return 2
	}
	resolveGlobals(&pa, deps)

	if len(pa.args) < 1 {
		writeError(deps.Stderr, pa.json, "secret ID or share URL is required")
		return 2
	}

	if pa.apiKey == "" {
		writeError(deps.Stderr, pa.json, "--api-key is required for burn")
		return 2
	}

	// Extract ID: might be a share URL or bare ID
	idOrURL := pa.args[0]
	secretID := idOrURL
	baseURL := pa.baseURL

	if strings.Contains(idOrURL, "/") || strings.Contains(idOrURL, "#") {
		id, _, err := envelope.ParseShareURL(idOrURL)
		if err != nil {
			writeError(deps.Stderr, pa.json, fmt.Sprintf("invalid URL: %v", err))
			return 2
		}
		secretID = id
		// Derive base URL from share URL if not explicitly set via flag/env
		if !pa.baseURLFromFlag && deps.Getenv("SECRET_BASE_URL") == "" {
			if u, err := url.Parse(idOrURL); err == nil && u.Scheme != "" {
				baseURL = u.Scheme + "://" + u.Host
			}
		}
	}

	client := &APIClient{
		BaseURL:    baseURL,
		APIKey:     pa.apiKey,
		HTTPClient: deps.HTTPClient,
	}

	if err := client.Burn(secretID); err != nil {
		writeError(deps.Stderr, pa.json, fmt.Sprintf("burn failed: %v", err))
		return 1
	}

	if pa.json {
		enc := json.NewEncoder(deps.Stdout)
		_ = enc.Encode(map[string]bool{"ok": true})
	} else {
		fmt.Fprintln(deps.Stderr, "Secret burned.")
	}

	return 0
}

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HTTPDoer is the interface for making HTTP requests.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// APIClient wraps HTTP calls to the secrt API.
type APIClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient HTTPDoer
}

// CreateRequest is the API payload for creating a secret.
type CreateRequest struct {
	Envelope   json.RawMessage `json:"envelope"`
	ClaimHash  string          `json:"claim_hash"`
	TTLSeconds *int64          `json:"ttl_seconds,omitempty"`
}

// CreateResponse is the API response from creating a secret.
type CreateResponse struct {
	ID        string `json:"id"`
	ShareURL  string `json:"share_url"`
	ExpiresAt string `json:"expires_at"`
}

// ClaimRequest is the API payload for claiming a secret.
type ClaimRequest struct {
	Claim string `json:"claim"`
}

// ClaimResponse is the API response from claiming a secret.
type ClaimResponse struct {
	Envelope  json.RawMessage `json:"envelope"`
	ExpiresAt string          `json:"expires_at"`
}

// Create uploads an encrypted envelope and returns the server response.
func (c *APIClient) Create(req CreateRequest) (CreateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CreateResponse{}, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := c.BaseURL + "/api/v1/public/secrets"
	if c.APIKey != "" {
		endpoint = c.BaseURL + "/api/v1/secrets"
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return CreateResponse{}, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("X-API-Key", c.APIKey)
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return CreateResponse{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return CreateResponse{}, readAPIError(resp)
	}

	var result CreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return CreateResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// Claim sends a claim token and returns the envelope.
func (c *APIClient) Claim(secretID string, claimToken []byte) (ClaimResponse, error) {
	req := ClaimRequest{
		Claim: encodeB64(claimToken),
	}
	body, err := json.Marshal(req)
	if err != nil {
		return ClaimResponse{}, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := c.BaseURL + "/api/v1/secrets/" + secretID + "/claim"
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ClaimResponse{}, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return ClaimResponse{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ClaimResponse{}, readAPIError(resp)
	}

	var result ClaimResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ClaimResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// Burn deletes a secret without claiming it.
func (c *APIClient) Burn(secretID string) error {
	endpoint := c.BaseURL + "/api/v1/secrets/" + secretID + "/burn"
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("X-API-Key", c.APIKey)
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return readAPIError(resp)
	}
	return nil
}

func readAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp.Error)
	}
	return fmt.Errorf("server error (%d)", resp.StatusCode)
}

func encodeB64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

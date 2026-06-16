// Package gateway provides clients for queries exposed by the internal
// GraphQL gateway (graphql-gateway.graphql-gateway.svc.cluster.local:4000).
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// GeoLocation holds the resolved location for an IP address.
type GeoLocation struct {
	City        string `json:"city"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Formatted   string `json:"formatted"`
}

// ParsedUserAgent holds the parsed components of a User-Agent string.
type ParsedUserAgent struct {
	Browser   string `json:"browser"`
	OS        string `json:"os"`
	Formatted string `json:"formatted"`
}

// LookupIP queries the gateway for the city/country associated with ip.
// Returns nil (no error) when the gateway has no record (e.g. private IPs).
// Errors only on network or protocol failures.
func LookupIP(ctx context.Context, client *http.Client, gatewayURL, ip string) (*GeoLocation, error) {
	const query = `query GeolocateIP($ip: String!) {
  geolocateIP(ip: $ip) { city country countryCode formatted }
}`
	var resp struct {
		Data struct {
			GeolocateIP *GeoLocation `json:"geolocateIP"`
		} `json:"data"`
	}
	if err := do(ctx, client, gatewayURL, query, map[string]any{"ip": ip}, &resp); err != nil {
		return nil, err
	}
	return resp.Data.GeolocateIP, nil
}

// ParseUserAgent queries the gateway to parse a raw User-Agent string into
// browser, OS, and a human-readable formatted string.
// Returns nil (no error) when the gateway cannot parse the value.
func ParseUserAgent(ctx context.Context, client *http.Client, gatewayURL, userAgent string) (*ParsedUserAgent, error) {
	const query = `query ParseUserAgent($ua: String!) {
  parseUserAgent(userAgent: $ua) { browser os formatted }
}`
	var resp struct {
		Data struct {
			ParseUserAgent *ParsedUserAgent `json:"parseUserAgent"`
		} `json:"data"`
	}
	if err := do(ctx, client, gatewayURL, query, map[string]any{"ua": userAgent}, &resp); err != nil {
		return nil, err
	}
	return resp.Data.ParseUserAgent, nil
}

// do executes a GraphQL query against the gateway and decodes the response
// into out. It is the shared transport used by all public functions in this
// package.
func do(ctx context.Context, client *http.Client, url, query string, variables map[string]any, out any) error {
	body, err := json.Marshal(struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}{Query: query, Variables: variables})
	if err != nil {
		return fmt.Errorf("gateway: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gateway: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway: unexpected status %d", resp.StatusCode)
	}

	// Decode into a wrapper that surfaces GraphQL-level errors.
	var envelope struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	// Decode twice: once into the error envelope, once into the caller's out.
	// We decode into a raw json.RawMessage first to avoid consuming the body.
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return fmt.Errorf("gateway: decode response: %w", err)
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && len(envelope.Errors) > 0 {
		return fmt.Errorf("gateway: %s", envelope.Errors[0].Message)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("gateway: decode data: %w", err)
	}
	return nil
}

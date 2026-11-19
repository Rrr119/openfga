// Package client contains a small HTTP client for the OpenFGA service that is
// sufficient for running RBAC migrations without pulling in the full Go SDK.
// It speaks the same public REST gateway exposed by the server, so everything
// written here is indistinguishable from traffic produced by any existing
// OpenFGA client.
package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

// HTTPClient calls the OpenFGA REST gateway.
type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
	token      string
	marshal    protojson.MarshalOptions
	unmarshal  protojson.UnmarshalOptions
}

// Option customizes an HTTPClient.
type Option func(*HTTPClient)

// WithHTTPClient injects a custom *http.Client (e.g. with custom timeouts).
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *HTTPClient) {
		c.httpClient = httpClient
	}
}

// WithToken sets a preshared key sent as an Authorization: Bearer token.
func WithToken(token string) Option {
	return func(c *HTTPClient) {
		c.token = token
	}
}

// New builds an HTTPClient for the given base URL, e.g.
// "http://localhost:8080". A trailing slash is tolerated.
func New(baseURL string, opts ...Option) *HTTPClient {
	c := &HTTPClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
		marshal:    protojson.MarshalOptions{EmitUnpopulated: false},
		unmarshal:  protojson.UnmarshalOptions{DiscardUnknown: true},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CreateStore creates a store and returns its id.
func (c *HTTPClient) CreateStore(ctx context.Context, name string) (string, error) {
	var resp openfgav1.CreateStoreResponse
	if err := c.post(ctx, "/stores", &openfgav1.CreateStoreRequest{Name: name}, &resp); err != nil {
		return "", err
	}
	return resp.GetId(), nil
}

// WriteAuthorizationModel uploads an authorization model and returns its id.
func (c *HTTPClient) WriteAuthorizationModel(
	ctx context.Context,
	storeID string,
	model *openfgav1.AuthorizationModel,
) (string, error) {
	var resp openfgav1.WriteAuthorizationModelResponse
	path := fmt.Sprintf("/stores/%s/authorization-models", storeID)
	if err := c.post(ctx, path, &openfgav1.WriteAuthorizationModelRequest{
		TypeDefinitions: model.GetTypeDefinitions(),
		SchemaVersion:   model.GetSchemaVersion(),
		Conditions:      model.GetConditions(),
	}, &resp); err != nil {
		return "", err
	}
	return resp.GetAuthorizationModelId(), nil
}

// Write issues a tuple write against the REST gateway.
func (c *HTTPClient) Write(ctx context.Context, req *openfgav1.WriteRequest) (*openfgav1.WriteResponse, error) {
	path := fmt.Sprintf("/stores/%s/write", req.GetStoreId())
	var resp openfgav1.WriteResponse
	if err := c.post(ctx, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Check issues a check against the REST gateway.
func (c *HTTPClient) Check(ctx context.Context, req *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
	path := fmt.Sprintf("/stores/%s/check", req.GetStoreId())
	var resp openfgav1.CheckResponse
	if err := c.post(ctx, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *HTTPClient) post(ctx context.Context, path string, body proto.Message, out proto.Message) error {
	payload, err := c.marshal.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("call POST %s: %w", path, err)
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return fmt.Errorf("POST %s returned %d: %s", path, httpResp.StatusCode, strings.TrimSpace(string(raw)))
	}

	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := c.unmarshal.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("unmarshal response from POST %s: %w", path, err)
	}
	return nil
}

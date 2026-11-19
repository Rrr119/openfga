package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

func TestHTTPClientCreateStore(t *testing.T) {
	var gotPath, gotAuth string
	var body map[string]any
	var handlerErr error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if r.Header.Get("Content-Type") != "application/json" {
			handlerErr = fmt.Errorf("unexpected content type %q", r.Header.Get("Content-Type"))
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			handlerErr = err
			return
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			handlerErr = err
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"01HSTORE","name":"rbac","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	apiClient := New(server.URL+"/", WithToken("secret"))
	storeID, err := apiClient.CreateStore(context.Background(), "rbac")
	require.NoError(t, err)
	require.NoError(t, handlerErr)
	require.Equal(t, "01HSTORE", storeID)
	require.Equal(t, "/stores", gotPath)
	require.Equal(t, "Bearer secret", gotAuth)
	require.Equal(t, "rbac", body["name"])
}

func TestHTTPClientWriteAuthorizationModelAndTuples(t *testing.T) {
	var paths []string
	var bodies []map[string]any
	var handlerErr error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			handlerErr = err
			return
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			handlerErr = err
			return
		}
		bodies = append(bodies, body)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/stores/store-1/authorization-models":
			_, _ = w.Write([]byte(`{"authorization_model_id":"model-1"}`))
		case "/stores/store-1/write":
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer server.Close()

	apiClient := New(server.URL)

	model := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.1",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "user"},
		},
	}
	modelID, err := apiClient.WriteAuthorizationModel(context.Background(), "store-1", model)
	require.NoError(t, err)
	require.NoError(t, handlerErr)
	require.Equal(t, "model-1", modelID)
	require.Equal(t, "1.1", bodies[0]["schema_version"])

	_, err = apiClient.Write(context.Background(), &openfgav1.WriteRequest{
		StoreId:              "store-1",
		AuthorizationModelId: "model-1",
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys:   []*openfgav1.TupleKey{{Object: "document:1", Relation: "viewer", User: "user:alice"}},
			OnDuplicate: "ignore",
		},
	})
	require.NoError(t, err)
	require.Equal(t, "/stores/store-1/write", paths[1])
	writes := bodies[1]["writes"].(map[string]any)
	require.Equal(t, "ignore", writes["on_duplicate"])
	tuples := writes["tuple_keys"].([]any)
	require.Len(t, tuples, 1)
	require.Equal(t, "document:1", tuples[0].(map[string]any)["object"])
}

func TestHTTPClientCheck(t *testing.T) {
	var handlerErr error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stores/store-1/check" {
			handlerErr = fmt.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	defer server.Close()

	apiClient := New(server.URL)
	resp, err := apiClient.Check(context.Background(), &openfgav1.CheckRequest{
		StoreId: "store-1",
		TupleKey: &openfgav1.CheckRequestTupleKey{
			Object: "document:1", Relation: "viewer", User: "user:alice",
		},
	})
	require.NoError(t, err)
	require.NoError(t, handlerErr)
	require.True(t, resp.GetAllowed())
}

func TestHTTPClientSurfacesServerErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer server.Close()

	_, err := New(server.URL).CreateStore(context.Background(), "x")
	require.ErrorContains(t, err, "returned 400")
	require.ErrorContains(t, err, "boom")
}

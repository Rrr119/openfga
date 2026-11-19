package rbacmigration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/pkg/migration/batchwriter"
	"github.com/openfga/openfga/pkg/migration/client"
	"github.com/openfga/openfga/pkg/migration/rbac"
	"github.com/openfga/openfga/pkg/testutils"
	oprgatests "github.com/openfga/openfga/tests"
)

// TestMigrationOverHTTPAPI drives the entire migration through the public REST
// gateway, exactly as the `openfga rbac-migrate` CLI does: create store,
// upload model, batch-write tuples, then verify authorization with Check.
func TestMigrationOverHTTPAPI(t *testing.T) {
	cfg := testutils.MustDefaultConfigWithRandomPorts()
	cfg.Datastore.Engine = "memory"
	cfg.Log.Level = "error"
	oprgatests.StartServer(t, cfg)

	spec := &rbac.Spec{
		Roles: []rbac.Role{
			{Name: "writer", Permissions: []string{"document:write", "document:read"}},
			{Name: "reader", Permissions: []string{"document:read"}},
		},
		Assignments: []rbac.Assignment{
			{Subject: "alice", Role: "writer", Resource: "document:1"},
			{Subject: "bob", Role: "reader", Resource: "document:1"},
			{Subject: "carol", Role: "reader", Resource: "document:2"},
		},
	}
	result, err := rbac.Migrate(spec)
	require.NoError(t, err)

	apiClient := client.New("http://" + cfg.HTTP.Addr)
	ctx := context.Background()

	storeID, err := apiClient.CreateStore(ctx, "rbac-http-migration")
	require.NoError(t, err)

	modelID, err := apiClient.WriteAuthorizationModel(ctx, storeID, result.Model)
	require.NotEmpty(t, modelID)
	require.NoError(t, err)

	writer := batchwriter.New(apiClient, storeID, modelID,
		batchwriter.WithBatchSize(2),
		batchwriter.WithMaxConcurrentWrites(2),
	)
	writeResult, err := writer.Write(ctx, result.TupleKeys)
	require.NoError(t, err)
	require.Equal(t, result.Stats.Tuples, writeResult.TuplesWritten)

	allowed, err := apiClient.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              storeID,
		AuthorizationModelId: modelID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			Object: "document:1", Relation: "write", User: "user:alice",
		},
	})
	require.NoError(t, err)
	require.True(t, allowed.GetAllowed())

	// Reader cannot write, and a reader on document:2 gets nothing on document:1.
	for _, denied := range []struct{ object, user string }{
		{"document:1", "user:bob"},
		{"document:1", "user:carol"},
	} {
		resp, checkErr := apiClient.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object: denied.object, Relation: "write", User: denied.user,
			},
		})
		require.NoError(t, checkErr)
		require.False(t, resp.GetAllowed())
	}

	// Re-running the write with ignore-duplicates succeeds against the live API.
	idempotent := batchwriter.New(apiClient, storeID, modelID, batchwriter.WithIgnoreDuplicates())
	_, err = idempotent.Write(ctx, result.TupleKeys)
	require.NoError(t, err)
}

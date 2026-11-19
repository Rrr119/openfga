// Package rbacmigration contains end-to-end tests that migrate a classic RBAC
// dataset into OpenFGA ReBAC and exercise the query APIs on the result.
package rbacmigration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/pkg/migration/batchwriter"
	"github.com/openfga/openfga/pkg/migration/rbac"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/tuple"
)

const (
	docCount       = 1000
	viewersPerDoc  = 90
	editorsPerDoc  = 8
	adminsPerDoc   = 2
	totalRelations = docCount * (viewersPerDoc + editorsPerDoc + adminsPerDoc) // 100_000
)

// buildLargeRBACSpec creates an RBAC spec with exactly 100,000 scoped role
// assignments: every document gets 90 viewers, 8 editors and 2 admins.
func buildLargeRBACSpec() *rbac.Spec {
	spec := &rbac.Spec{
		Roles: []rbac.Role{
			{Name: "viewer", Permissions: []string{"document:can_view"}},
			{Name: "editor", Permissions: []string{"document:can_edit", "document:can_view"}},
			{Name: "admin", Permissions: []string{"document:can_delete", "document:can_edit", "document:can_view"}},
		},
	}

	assignments := make([]rbac.Assignment, 0, totalRelations)
	for docID := 0; docID < docCount; docID++ {
		resource := fmt.Sprintf("document:%d", docID)
		for i := 0; i < viewersPerDoc; i++ {
			assignments = append(assignments, rbac.Assignment{
				Subject:  fmt.Sprintf("user-%d-%d-v", docID, i),
				Role:     "viewer",
				Resource: resource,
			})
		}
		for i := 0; i < editorsPerDoc; i++ {
			assignments = append(assignments, rbac.Assignment{
				Subject:  fmt.Sprintf("user-%d-%d-e", docID, i),
				Role:     "editor",
				Resource: resource,
			})
		}
		for i := 0; i < adminsPerDoc; i++ {
			assignments = append(assignments, rbac.Assignment{
				Subject:  fmt.Sprintf("user-%d-%d-a", docID, i),
				Role:     "admin",
				Resource: resource,
			})
		}
	}
	spec.Assignments = assignments
	return spec
}

func TestMigrate100kRelationshipsAndQuery(t *testing.T) {
	require.Equal(t, 100_000, totalRelations, "test fixture must represent 100k relationships")

	ctx := context.Background()

	// 1. Migrate the RBAC source model into a ReBAC model + tuple keys.
	migrationStart := time.Now()
	result, err := rbac.Migrate(buildLargeRBACSpec())
	require.NoError(t, err)
	require.Equal(t, totalRelations, result.Stats.Tuples)
	require.Empty(t, result.Warnings)
	t.Logf("migrated RBAC spec into %d tuples in %s", result.Stats.Tuples, time.Since(migrationStart))

	// 2. Boot an in-process OpenFGA server on the in-memory datastore. The
	// migration only uses the public APIs, exactly as an external client would.
	datastore := memory.New()
	t.Cleanup(datastore.Close)

	srv, err := server.NewServerWithOpts(server.WithDatastore(datastore))
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	storeResp, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "rbac-migration-100k"})
	require.NoError(t, err)
	storeID := storeResp.GetId()

	modelResp, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         storeID,
		SchemaVersion:   result.Model.GetSchemaVersion(),
		TypeDefinitions: result.Model.GetTypeDefinitions(),
		Conditions:      result.Model.GetConditions(),
	})
	require.NoError(t, err)
	modelID := modelResp.GetAuthorizationModelId()

	// 3. Batch-write all 100k tuples through the existing Write API. The
	// datastore caps each request at 100 tuples, so this must fan out into
	// 1000 batched requests.
	writer := batchwriter.New(srv, storeID, modelID,
		batchwriter.WithBatchSize(100),
		batchwriter.WithMaxConcurrentWrites(8),
	)
	writeStart := time.Now()
	writeResult, err := writer.Write(ctx, result.TupleKeys)
	require.NoError(t, err)
	require.Equal(t, totalRelations, writeResult.TuplesWritten)
	require.Equal(t, totalRelations/100, writeResult.Batches)
	t.Logf("batch wrote %d tuples in %d batches in %s", writeResult.TuplesWritten, writeResult.Batches, time.Since(writeStart))

	// 4. Confirm the full dataset landed by paging through the Read API.
	require.Eventually(t, func() bool {
		count := countAllTuples(t, ctx, srv, storeID)
		return count == totalRelations
	}, 30*time.Second, 100*time.Millisecond, "all migrated tuples must be readable")

	// 5. Query checks across documents and roles.
	checkStart := time.Now()

	// Direct role grants.
	assertCheck(t, ctx, srv, storeID, modelID, "document:0", "can_view", "user:user-0-0-v", true)
	assertCheck(t, ctx, srv, storeID, modelID, "document:42", "can_edit", "user:user-42-0-e", true)
	assertCheck(t, ctx, srv, storeID, modelID, "document:999", "can_delete", "user:user-999-0-a", true)

	// Permission inheritance: editors can view, admins can edit and view.
	assertCheck(t, ctx, srv, storeID, modelID, "document:7", "can_view", "user:user-7-0-e", true)
	assertCheck(t, ctx, srv, storeID, modelID, "document:7", "can_edit", "user:user-7-0-a", true)
	assertCheck(t, ctx, srv, storeID, modelID, "document:7", "can_view", "user:user-7-1-a", true)

	// A viewer cannot edit or delete, and nobody inherits a role across documents.
	assertCheck(t, ctx, srv, storeID, modelID, "document:0", "can_edit", "user:user-0-0-v", false)
	assertCheck(t, ctx, srv, storeID, modelID, "document:0", "can_delete", "user:user-0-0-v", false)
	assertCheck(t, ctx, srv, storeID, modelID, "document:1", "can_view", "user:user-0-0-v", false)
	assertCheck(t, ctx, srv, storeID, modelID, "document:5", "can_view", "user:user-5-99-v", false) // id 99 was never assigned

	// ListObjects must reconstruct the viewer set for a document.
	listResp, err := srv.ListObjects(ctx, &openfgav1.ListObjectsRequest{
		StoreId:              storeID,
		AuthorizationModelId: modelID,
		User:                 "user:user-3-0-v",
		Type:                 "document",
		Relation:             "can_view",
	})
	require.NoError(t, err)
	require.Contains(t, listResp.GetObjects(), "document:3")
	require.NotContains(t, listResp.GetObjects(), "document:4")

	t.Logf("ran authorization queries in %s", time.Since(checkStart))

	// 6. Re-running with ignore-duplicates must be idempotent.
	idempotentWriter := batchwriter.New(srv, storeID, modelID,
		batchwriter.WithBatchSize(100),
		batchwriter.WithIgnoreDuplicates(),
	)
	_, err = idempotentWriter.Write(ctx, result.TupleKeys[:1000])
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return countAllTuples(t, ctx, srv, storeID) == totalRelations
	}, 30*time.Second, 100*time.Millisecond, "idempotent re-run must not create duplicate tuples")
}

func assertCheck(
	t *testing.T,
	ctx context.Context,
	srv *server.Server,
	storeID, modelID, object, relation, user string,
	allowed bool,
) {
	t.Helper()
	resp, err := srv.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              storeID,
		AuthorizationModelId: modelID,
		TupleKey:             tuple.NewCheckRequestTupleKey(object, relation, user),
	})
	require.NoError(t, err)
	require.Equal(t, allowed, resp.GetAllowed(), "check %s#%s@%s", object, relation, user)
}

func countAllTuples(t *testing.T, ctx context.Context, srv *server.Server, storeID string) int {
	t.Helper()
	total := 0
	pageToken := ""
	for {
		resp, err := srv.Read(ctx, &openfgav1.ReadRequest{
			StoreId:           storeID,
			PageSize:          wrapperspb.Int32(100),
			ContinuationToken: pageToken,
		})
		require.NoError(t, err)
		total += len(resp.GetTuples())
		pageToken = resp.GetContinuationToken()
		if pageToken == "" {
			break
		}
	}
	return total
}

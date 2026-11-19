package rbacmigration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/pkg/migration/rbac"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/tuple"
)

func TestMigratedModelPreservesRBACSemantics(t *testing.T) {
	ctx := context.Background()

	spec := &rbac.Spec{
		Roles: []rbac.Role{
			// Unqualified "read" applies to every resource type in the spec.
			{Name: "auditor", Permissions: []string{"read"}},
			{Name: "owner", Permissions: []string{"document:delete"}},
		},
		Resources: []string{"document:1", "folder:1"},
		Assignments: []rbac.Assignment{
			// Global role: alice audits every document and folder.
			{Subject: "alice", Role: "auditor"},
			// Group membership: the platform team owns document:1.
			{Subject: "platform", Kind: rbac.SubjectKindGroup, Role: "owner", Resource: "document:1"},
			// Nested group member expressed via a group assignment is outside
			// the RBAC input; bob is a plain group member represented as a user.
			{Subject: "bob", Role: "auditor", Resource: "document:2"},
		},
	}

	result, err := rbac.Migrate(spec)
	require.NoError(t, err)

	datastore := memory.New()
	t.Cleanup(datastore.Close)

	srv, err := server.NewServerWithOpts(server.WithDatastore(datastore))
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	storeResp, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "rbac-semantics"})
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

	_, err = srv.Write(ctx, &openfgav1.WriteRequest{
		StoreId:              storeID,
		AuthorizationModelId: modelID,
		Writes:               &openfgav1.WriteRequestWrites{TupleKeys: result.TupleKeys},
	})
	require.NoError(t, err)

	// Group membership itself is an OpenFGA tuple on group#assignee; the RBAC
	// spec only migrates role bindings, so wire bob's membership explicitly the
	// way an operator would for pre-existing groups.
	_, err = srv.Write(ctx, &openfgav1.WriteRequest{
		StoreId:              storeID,
		AuthorizationModelId: modelID,
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{
			tuple.NewTupleKey("group:platform", "assignee", "user:carol"),
		}},
	})
	require.NoError(t, err)

	// Global role expands across every enumerated resource and every type.
	assertCheck(t, ctx, srv, storeID, modelID, "document:1", "read", "user:alice", true)
	assertCheck(t, ctx, srv, storeID, modelID, "folder:1", "read", "user:alice", true)

	// Scoped assignment applies only to its resource.
	assertCheck(t, ctx, srv, storeID, modelID, "document:2", "read", "user:bob", true)
	assertCheck(t, ctx, srv, storeID, modelID, "document:1", "read", "user:bob", false)

	// Group-held role grants the permission to group members, not the group object itself.
	assertCheck(t, ctx, srv, storeID, modelID, "document:1", "delete", "user:carol", true)
	assertCheck(t, ctx, srv, storeID, modelID, "document:2", "delete", "user:carol", false)

	// The unqualified permission exists on both resource types.
	assertCheck(t, ctx, srv, storeID, modelID, "folder:1", "read", "user:bob", false)

	// Unknown users get nothing.
	assertCheck(t, ctx, srv, storeID, modelID, "document:1", "read", "user:nobody", false)
}

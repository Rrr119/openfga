package rbac

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"
)

func TestParseSpec(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		spec, err := ParseSpec([]byte(`{"roles":[{"name":"admin","permissions":["document:delete"]}],"assignments":[]}`))
		require.NoError(t, err)
		require.Len(t, spec.Roles, 1)
		require.Equal(t, "admin", spec.Roles[0].Name)
	})

	t.Run("yaml", func(t *testing.T) {
		spec, err := ParseSpec([]byte(`
roles:
  - name: viewer
    permissions: [viewer]
assignments:
  - subject: alice
    role: viewer
    resource: document:1
`))
		require.NoError(t, err)
		require.Len(t, spec.Assignments, 1)
		require.Empty(t, spec.Assignments[0].Kind)

		result, err := Migrate(spec)
		require.NoError(t, err)
		require.Contains(t, tuplesToStrings(result.TupleKeys), "document:1#viewer_binding@user:alice")
	})

	t.Run("invalid yaml", func(t *testing.T) {
		_, err := ParseSpec([]byte("{not yaml"))
		require.Error(t, err)
	})
}

func TestMigrateScopedAssignments(t *testing.T) {
	spec := &Spec{
		Roles: []Role{
			{Name: "admin", Permissions: []string{"document:owner", "document:writer"}},
			{Name: "viewer", Permissions: []string{"document:viewer"}},
		},
		Assignments: []Assignment{
			{Subject: "alice", Role: "admin", Resource: "document:1"},
			{Subject: "bob", Kind: SubjectKindGroup, Role: "viewer", Resource: "document:1"},
			{Subject: "carol", Role: "viewer", Resource: "document:2"},
			// duplicate of the first assignment must be collapsed with a warning
			{Subject: "alice", Role: "admin", Resource: "document:1"},
		},
	}

	result, err := Migrate(spec)
	require.NoError(t, err)

	// Every generated model must parse as a valid OpenFGA model.
	_, err = parser.TransformDSLToProto(result.DSL)
	require.NoError(t, err)
	require.NotNil(t, result.Model)

	require.Contains(t, result.DSL, "type user")
	require.Contains(t, result.DSL, "type group")
	require.Contains(t, result.DSL, "type role")
	require.Contains(t, result.DSL, "define admin_binding: [user, group#assignee, role#assignee]")
	require.Contains(t, result.DSL, "define viewer_binding: [user, group#assignee, role#assignee]")
	require.Contains(t, result.DSL, "define owner: admin_binding")
	require.Contains(t, result.DSL, "define writer: admin_binding")
	require.Contains(t, result.DSL, "define viewer: viewer_binding")

	require.Equal(t, Stats{Roles: 2, ResourceTypes: 1, Assignments: 4, Tuples: 3, Duplicates: 1}, result.Stats)
	require.Len(t, result.Warnings, 1)

	tupleStrings := tuplesToStrings(result.TupleKeys)
	require.Contains(t, tupleStrings, "document:1#admin_binding@user:alice")
	require.Contains(t, tupleStrings, "document:1#viewer_binding@group:bob#assignee")
	require.Contains(t, tupleStrings, "document:2#viewer_binding@user:carol")
	require.Len(t, tupleStrings, 3)

	// Output must be deterministic.
	result2, err := Migrate(spec)
	require.NoError(t, err)
	require.Equal(t, result.DSL, result2.DSL)
	require.Equal(t, tuplesToStrings(result.TupleKeys), tuplesToStrings(result2.TupleKeys))
}

func TestMigrateGlobalAssignments(t *testing.T) {
	spec := &Spec{
		Roles: []Role{
			{Name: "admin", Permissions: []string{"document:owner"}},
		},
		Resources: []string{"document:1", "document:2", "document:3"},
		Assignments: []Assignment{
			{Subject: "alice", Role: "admin"},
			{Subject: "eng", Kind: SubjectKindGroup, Role: "admin"},
			{Subject: "bob", Role: "admin", Resource: "document:4"},
		},
	}

	result, err := Migrate(spec)
	require.NoError(t, err)

	// 2 role#assignee tuples + 1 global link tuple per enumerated resource
	// (document:1..3) + 1 scoped tuple for document:4.
	require.Equal(t, 7, result.Stats.Tuples)

	tupleStrings := tuplesToStrings(result.TupleKeys)
	require.Contains(t, tupleStrings, "role:admin#assignee@user:alice")
	require.Contains(t, tupleStrings, "role:admin#assignee@group:eng")
	require.Contains(t, tupleStrings, "document:1#admin_binding@role:admin#assignee")
	require.Contains(t, tupleStrings, "document:2#admin_binding@role:admin#assignee")
	require.Contains(t, tupleStrings, "document:4#admin_binding@user:bob")

	// document:4 is inferred as a resource even though it is not in Resources.
	require.Contains(t, result.DSL, "type document")
}

func TestMigrateUnqualifiedPermissionAppliesToAllResourceTypes(t *testing.T) {
	spec := &Spec{
		Roles: []Role{
			{Name: "auditor", Permissions: []string{"read"}},
		},
		Assignments: []Assignment{
			{Subject: "alice", Role: "auditor", Resource: "document:1"},
			{Subject: "alice", Role: "auditor", Resource: "folder:1"},
		},
	}

	result, err := Migrate(spec)
	require.NoError(t, err)
	require.Contains(t, result.DSL, "type document")
	require.Contains(t, result.DSL, "type folder")
	require.Equal(t, 2, strings.Count(result.DSL, "define read: auditor_binding"))
}

func TestMigrateValidationErrors(t *testing.T) {
	t.Run("nil spec", func(t *testing.T) {
		_, err := Migrate(nil)
		require.ErrorContains(t, err, "nil")
	})

	t.Run("no roles", func(t *testing.T) {
		_, err := Migrate(&Spec{})
		require.ErrorContains(t, err, "at least one role")
	})

	t.Run("duplicate role", func(t *testing.T) {
		_, err := Migrate(&Spec{Roles: []Role{{Name: "a"}, {Name: "a"}}})
		require.ErrorContains(t, err, "duplicate role")
	})

	t.Run("invalid relation name", func(t *testing.T) {
		_, err := Migrate(&Spec{Roles: []Role{{Name: "bad name"}}})
		require.ErrorContains(t, err, "not a valid OpenFGA relation")
	})

	t.Run("unknown role in assignment", func(t *testing.T) {
		_, err := Migrate(&Spec{
			Roles:       []Role{{Name: "admin"}},
			Assignments: []Assignment{{Subject: "alice", Role: "ghost"}},
		})
		require.ErrorContains(t, err, "unknown role")
	})

	t.Run("invalid resource", func(t *testing.T) {
		_, err := Migrate(&Spec{
			Roles:       []Role{{Name: "admin"}},
			Assignments: []Assignment{{Subject: "alice", Role: "admin", Resource: "no-colon"}},
		})
		require.ErrorContains(t, err, "not a valid object")
	})

	t.Run("unsupported subject kind", func(t *testing.T) {
		_, err := Migrate(&Spec{
			Roles:       []Role{{Name: "admin"}},
			Assignments: []Assignment{{Subject: "alice", Role: "admin", Kind: "service-account"}},
		})
		require.ErrorContains(t, err, "unsupported kind")
	})

	t.Run("global assignments without resources", func(t *testing.T) {
		_, err := Migrate(&Spec{
			Roles:       []Role{{Name: "admin"}},
			Assignments: []Assignment{{Subject: "alice", Role: "admin"}},
		})
		require.ErrorContains(t, err, "global assignments require resources")
	})

	t.Run("malformed qualified permission", func(t *testing.T) {
		_, err := Migrate(&Spec{Roles: []Role{{Name: "admin", Permissions: []string{"document:"}}}})
		require.ErrorContains(t, err, "malformed qualified permission")
	})

	t.Run("permission collides with generated binding", func(t *testing.T) {
		_, err := Migrate(&Spec{Roles: []Role{{
			Name:        "admin",
			Permissions: []string{"document:admin_binding"},
		}}})
		require.ErrorContains(t, err, "collides with the generated binding relation")
	})
}

func tuplesToStrings(tupleKeys []*openfgav1.TupleKey) []string {
	result := make([]string, 0, len(tupleKeys))
	for _, tupleKey := range tupleKeys {
		result = append(result, tupleKey.GetObject()+"#"+tupleKey.GetRelation()+"@"+tupleKey.GetUser())
	}
	return result
}

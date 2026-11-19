package rbac

import (
	"fmt"
	"sort"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"

	tupleUtils "github.com/openfga/openfga/pkg/tuple"
)

// bindingSuffix is appended to a role name to form the relation on each
// resource type that holds every direct (scoped) assignment as well as the
// role objects that represent globally assigned roles.
const bindingSuffix = "_binding"

// Stats summarizes a migration run.
type Stats struct {
	Roles         int
	ResourceTypes int
	Assignments   int
	// Tuples is the number of distinct relationship tuples produced.
	Tuples int
	// Duplicates is the number of repeated input assignments that were
	// collapsed into a single tuple.
	Duplicates int
}

// Result is the output of a successful migration.
type Result struct {
	// DSL is the generated OpenFGA authorization model in DSL 1.1 syntax.
	DSL string
	// Model is the parsed authorization model, ready for WriteAuthorizationModel.
	Model *openfgav1.AuthorizationModel
	// TupleKeys are the relationship tuples that recreate the RBAC
	// assignments inside the ReBAC model.
	TupleKeys []*openfgav1.TupleKey
	// Warnings lists non-fatal issues, such as deduplicated assignments.
	Warnings []string
	Stats    Stats
}

// permission models a parsed Role.Permissions entry.
type permission struct {
	relation string
	// resourceType is empty for unqualified permissions, which apply to
	// every resource type.
	resourceType string
}

// Migrate converts an RBAC spec into an OpenFGA DSL model and the tuple keys
// representing the existing assignments.
//
// The generated model uses a "role" object type with an "assignee" relation
// (the role-as-group pattern) plus one "<role>_binding" relation per role on
// each resource type. Global assignments are expanded as role objects, so a
// global assignment costs one "role#assignee" tuple plus one link tuple per
// resource instead of one tuple per subject per resource.
func Migrate(spec *Spec) (*Result, error) {
	if spec == nil {
		return nil, fmt.Errorf("rbac spec is nil")
	}
	if len(spec.Roles) == 0 {
		return nil, fmt.Errorf("rbac spec must define at least one role")
	}

	rolePermissions := make(map[string][]permission, len(spec.Roles))
	resourceTypes := make(map[string]struct{})
	for _, role := range spec.Roles {
		if strings.TrimSpace(role.Name) == "" {
			return nil, fmt.Errorf("role name cannot be empty")
		}
		if !tupleUtils.IsValidRelation(role.Name) {
			return nil, fmt.Errorf("role name %q is not a valid OpenFGA relation", role.Name)
		}
		if _, exists := rolePermissions[role.Name]; exists {
			return nil, fmt.Errorf("duplicate role definition: %q", role.Name)
		}

		perms := make([]permission, 0, len(role.Permissions))
		for _, raw := range role.Permissions {
			perm, err := parsePermission(raw)
			if err != nil {
				return nil, fmt.Errorf("role %q: %w", role.Name, err)
			}
			if perm.relation == role.Name+bindingSuffix {
				return nil, fmt.Errorf(
					"role %q: permission %q collides with the generated binding relation %q; rename the permission",
					role.Name, raw, role.Name+bindingSuffix,
				)
			}
			perms = append(perms, perm)
			if perm.resourceType != "" {
				resourceTypes[perm.resourceType] = struct{}{}
			}
		}
		rolePermissions[role.Name] = perms
	}

	usesGroups := false
	for _, assignment := range spec.Assignments {
		if assignment.Kind == "" {
			assignment.Kind = SubjectKindUser
		}
		if assignment.Kind != SubjectKindUser && assignment.Kind != SubjectKindGroup {
			return nil, fmt.Errorf("assignment for subject %q has unsupported kind %q", assignment.Subject, assignment.Kind)
		}
		if assignment.Kind == SubjectKindGroup {
			usesGroups = true
		}
	}

	scopedRolesByType := make(map[string]map[string]struct{})
	globalRoles := make(map[string]struct{})
	seenAssignments := make(map[string]struct{})
	tuples := make(map[string]*openfgav1.TupleKey)
	var warnings []string

	addTuple := func(tk *openfgav1.TupleKey) {
		key := tupleUtils.TupleKeyToString(tk)
		if _, exists := tuples[key]; exists {
			return
		}
		tuples[key] = tk
	}

	for _, assignment := range spec.Assignments {
		if strings.TrimSpace(assignment.Subject) == "" {
			return nil, fmt.Errorf("assignment subject cannot be empty")
		}
		if !tupleUtils.IsValidUserID(assignment.Subject) {
			return nil, fmt.Errorf("subject id %q is not a valid OpenFGA identifier", assignment.Subject)
		}
		if _, ok := rolePermissions[assignment.Role]; !ok {
			return nil, fmt.Errorf("assignment for subject %q references unknown role %q", assignment.Subject, assignment.Role)
		}

		subjectType := string(SubjectKindUser)
		if assignment.Kind == SubjectKindGroup {
			subjectType = string(SubjectKindGroup)
		}
		subject := fmt.Sprintf("%s:%s", subjectType, assignment.Subject)

		dedupeKey := strings.Join([]string{subject, assignment.Role, assignment.Resource}, "|")
		if _, exists := seenAssignments[dedupeKey]; exists {
			warnings = append(warnings, fmt.Sprintf("duplicate assignment %q to role %q ignored", subject, assignment.Role))
			continue
		}
		seenAssignments[dedupeKey] = struct{}{}

		if assignment.Resource == "" {
			globalRoles[assignment.Role] = struct{}{}
			addTuple(tupleUtils.NewTupleKey(
				"role:"+assignment.Role,
				"assignee",
				subject,
			))
			continue
		}

		resourceType, err := validateResource(assignment.Resource)
		if err != nil {
			return nil, fmt.Errorf("assignment for subject %q: %w", assignment.Subject, err)
		}
		resourceTypes[resourceType] = struct{}{}
		if _, ok := scopedRolesByType[resourceType]; !ok {
			scopedRolesByType[resourceType] = make(map[string]struct{})
		}
		scopedRolesByType[resourceType][assignment.Role] = struct{}{}
		user := subject
		if assignment.Kind == SubjectKindGroup {
			user = subject + "#assignee"
		}
		addTuple(tupleUtils.NewTupleKey(
			assignment.Resource,
			assignment.Role+bindingSuffix,
			user,
		))
	}

	for _, resource := range spec.Resources {
		resourceType, err := validateResource(resource)
		if err != nil {
			return nil, err
		}
		resourceTypes[resourceType] = struct{}{}
	}

	if len(globalRoles) > 0 && len(resourceTypes) == 0 {
		return nil, fmt.Errorf("global assignments require resources: set spec.resources or provide scoped assignments")
	}

	// Every globally assigned role links into the binding relation of every
	// resource; the role object's assignee relation expands to the subjects.
	resources := make([]string, 0, len(spec.Resources))
	seenResources := make(map[string]struct{})
	for _, resource := range spec.Resources {
		if _, ok := seenResources[resource]; ok {
			continue
		}
		seenResources[resource] = struct{}{}
		resources = append(resources, resource)
	}
	for _, assignment := range spec.Assignments {
		if assignment.Resource == "" {
			continue
		}
		if _, ok := seenResources[assignment.Resource]; ok {
			continue
		}
		seenResources[assignment.Resource] = struct{}{}
		resources = append(resources, assignment.Resource)
	}
	sort.Strings(resources)

	for resourceType := range resourceTypes {
		if _, ok := scopedRolesByType[resourceType]; !ok {
			scopedRolesByType[resourceType] = make(map[string]struct{})
		}
		for role := range globalRoles {
			scopedRolesByType[resourceType][role] = struct{}{}
		}
	}
	for _, resource := range resources {
		for role := range globalRoles {
			addTuple(tupleUtils.NewTupleKey(
				resource,
				role+bindingSuffix,
				fmt.Sprintf("role:%s#assignee", role),
			))
		}
	}

	dsl := buildDSL(rolePermissions, resourceTypes, scopedRolesByType, usesGroups)
	model, err := parser.TransformDSLToProto(dsl)
	if err != nil {
		return nil, fmt.Errorf("generated model failed to parse: %w", err)
	}

	tupleKeys := make([]*openfgav1.TupleKey, 0, len(tuples))
	for _, tk := range tuples {
		tupleKeys = append(tupleKeys, tk)
	}
	sort.Slice(tupleKeys, func(i, j int) bool {
		return tupleUtils.TupleKeyToString(tupleKeys[i]) < tupleUtils.TupleKeyToString(tupleKeys[j])
	})

	return &Result{
		DSL:       dsl,
		Model:     model,
		TupleKeys: tupleKeys,
		Warnings:  warnings,
		Stats: Stats{
			Roles:         len(rolePermissions),
			ResourceTypes: len(resourceTypes),
			Assignments:   len(spec.Assignments),
			Tuples:        len(tupleKeys),
			Duplicates:    len(warnings),
		},
	}, nil
}

func parsePermission(raw string) (permission, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return permission{}, fmt.Errorf("permission cannot be empty")
	}
	if strings.Contains(raw, ":") {
		resourceType, relation, found := strings.Cut(raw, ":")
		if !found || resourceType == "" || relation == "" || strings.Contains(relation, ":") {
			return permission{}, fmt.Errorf("malformed qualified permission %q, expected type:relation", raw)
		}
		if !tupleUtils.IsValidRelation(resourceType) || !tupleUtils.IsValidRelation(relation) {
			return permission{}, fmt.Errorf("permission %q contains invalid characters", raw)
		}
		return permission{resourceType: resourceType, relation: relation}, nil
	}
	if !tupleUtils.IsValidRelation(raw) {
		return permission{}, fmt.Errorf("permission %q contains invalid characters", raw)
	}
	return permission{relation: raw}, nil
}

func validateResource(resource string) (string, error) {
	if !tupleUtils.IsValidObject(resource) {
		return "", fmt.Errorf("resource %q is not a valid object of the form type:id", resource)
	}
	resourceType, _ := splitResource(resource)
	return resourceType, nil
}

func splitResource(resource string) (string, string) {
	resourceType, id, found := strings.Cut(resource, ":")
	if !found {
		return resource, ""
	}
	return resourceType, id
}

// buildDSL renders the deterministic OpenFGA model for the migration.
func buildDSL(
	rolePermissions map[string][]permission,
	resourceTypes map[string]struct{},
	bindingRolesByType map[string]map[string]struct{},
	usesGroups bool,
) string {
	var sb strings.Builder
	sb.WriteString("model\n  schema 1.1\n")

	// Principal and role types are stable and always present.
	sb.WriteString("\ntype user\n")
	if usesGroups {
		sb.WriteString("\ntype group\n  relations\n    define assignee: [user, group#assignee]\n")
	}
	sb.WriteString("\ntype role\n  relations\n    define assignee: [user")
	if usesGroups {
		sb.WriteString(", group#assignee")
	}
	sb.WriteString("]\n")

	// permissionRelations maps resource type -> permission relation -> roles
	// granting that permission.
	permissionRelations := make(map[string]map[string][]string)
	for resourceType := range resourceTypes {
		permissionRelations[resourceType] = make(map[string][]string)
	}
	for role, perms := range rolePermissions {
		for _, perm := range perms {
			targets := []string{perm.resourceType}
			if perm.resourceType == "" {
				targets = targets[:0]
				for resourceType := range resourceTypes {
					targets = append(targets, resourceType)
				}
			}
			for _, resourceType := range targets {
				permissionRelations[resourceType][perm.relation] = append(
					permissionRelations[resourceType][perm.relation], role,
				)
			}
		}
	}

	sortedResourceTypes := sortedKeys(resourceTypes)
	for _, resourceType := range sortedResourceTypes {
		sb.WriteString("\ntype ")
		sb.WriteString(resourceType)
		sb.WriteString("\n  relations\n")

		bindingRoles := sortedKeys(bindingRolesByType[resourceType])
		for _, role := range bindingRoles {
			sb.WriteString("    define ")
			sb.WriteString(role)
			sb.WriteString(bindingSuffix)
			sb.WriteString(": [user")
			if usesGroups {
				sb.WriteString(", group#assignee")
			}
			sb.WriteString(", role#assignee]\n")
		}

		permissions := permissionRelations[resourceType]
		for _, relation := range sortedKeys(permissions) {
			rolesGranting := append([]string(nil), permissions[relation]...)
			sort.Strings(rolesGranting)
			sb.WriteString("    define ")
			sb.WriteString(relation)
			sb.WriteString(": ")
			for i, role := range rolesGranting {
				if i > 0 {
					sb.WriteString(" or ")
				}
				sb.WriteString(role)
				sb.WriteString(bindingSuffix)
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Package rbac converts a classic RBAC model (roles, permissions and
// subject-to-role assignments) into an OpenFGA ReBAC authorization model
// (expressed in the OpenFGA DSL) plus the relationship tuples that carry the
// existing assignments over.
//
// The conversion is intentionally built on top of the public OpenFGA APIs
// (WriteAuthorizationModel and Write), so migrated data is fully compatible
// with every existing Check/ListObjects/ListUsers client.
package rbac

import (
	"os"

	"sigs.k8s.io/yaml"
)

// SubjectKind enumerates the kinds of subjects an RBAC assignment can target.
type SubjectKind string

const (
	// SubjectKindUser is the default: an individual user, e.g. "user:alice".
	SubjectKindUser SubjectKind = "user"
	// SubjectKindGroup maps to a group object; groups gain an "assignee"
	// relation so users can be members of a group that holds a role.
	SubjectKindGroup SubjectKind = "group"
)

// Role describes a single RBAC role and the permissions it grants.
//
// A permission is either qualified ("document:viewer") and applies to the
// named resource type only, or unqualified ("viewer") and applies to every
// resource type discovered in the input.
type Role struct {
	Name        string   `json:"name"        yaml:"name"`
	Permissions []string `json:"permissions" yaml:"permissions"`
}

// Assignment binds a subject to a role, either globally (when Resource is
// empty) or scoped to a single resource.
type Assignment struct {
	// Subject is the subject id without a type prefix, e.g. "alice".
	Subject string `json:"subject" yaml:"subject"`
	// Kind is "user" (default when empty) or "group".
	Kind SubjectKind `json:"kind,omitempty" yaml:"kind,omitempty"`
	// Role is the name of the assigned role.
	Role string `json:"role" yaml:"role"`
	// Resource is an optional fully-qualified resource, e.g. "document:42".
	// Empty means the assignment holds for every resource.
	Resource string `json:"resource,omitempty" yaml:"resource,omitempty"`
}

// Spec is the RBAC source model consumed by the migration tool.
type Spec struct {
	// Roles defines every role and its permissions.
	Roles []Role `json:"roles" yaml:"roles"`
	// Assignments are the existing subject-to-role bindings.
	Assignments []Assignment `json:"assignments" yaml:"assignments"`
	// Resources optionally enumerates the resources that global assignments
	// are expanded onto. When empty, resources are inferred from scoped
	// assignments; an error is returned if global assignments exist and no
	// resources can be inferred.
	Resources []string `json:"resources,omitempty" yaml:"resources,omitempty"`
}

// LoadSpec reads an RBAC spec from disk. Both JSON and YAML are accepted; the
// format is detected from the file content rather than its extension.
func LoadSpec(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSpec(data)
}

// ParseSpec decodes a JSON or YAML encoded RBAC spec.
func ParseSpec(data []byte) (*Spec, error) {
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

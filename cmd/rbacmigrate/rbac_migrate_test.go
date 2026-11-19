package rbacmigrate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const demoSpec = `
roles:
  - name: admin
    permissions: [document:owner, document:viewer]
  - name: viewer
    permissions: [document:viewer]
resources:
  - document:1
assignments:
  - subject: alice
    role: admin
  - subject: bob
    role: viewer
    resource: document:1
`

func writeSpec(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	return path
}

func TestRBACMigrateDryRun(t *testing.T) {
	dir := t.TempDir()
	specPath := writeSpec(t, dir, "rbac.yaml", demoSpec)
	modelPath := filepath.Join(dir, "model.fga")

	cmd := NewRBACMigrateCommand()
	cmd.SetArgs([]string{
		"--input", specPath,
		"--model-output", modelPath,
	})
	require.NoError(t, cmd.Execute())

	model, err := os.ReadFile(modelPath)
	require.NoError(t, err)
	require.Contains(t, string(model), "model")
	require.Contains(t, string(model), "type document")
	require.Contains(t, string(model), "define owner: admin_binding")
}

func TestRBACMigrateRejectsMissingInput(t *testing.T) {
	cmd := NewRBACMigrateCommand()
	cmd.SetArgs(nil)
	require.Error(t, cmd.Execute())
}

func TestRBACMigrateRejectsUnknownInputFile(t *testing.T) {
	cmd := NewRBACMigrateCommand()
	cmd.SetArgs([]string{"--input", filepath.Join(t.TempDir(), "missing.json")})
	require.ErrorContains(t, cmd.Execute(), "load RBAC spec")
}

func TestRBACMigrateRejectsInvalidSpec(t *testing.T) {
	dir := t.TempDir()
	specPath := writeSpec(t, dir, "bad.yaml", "roles: []\nassignments: []\n")

	cmd := NewRBACMigrateCommand()
	cmd.SetArgs([]string{
		"--input", specPath,
		"--model-output", filepath.Join(dir, "model.fga"),
	})
	require.ErrorContains(t, cmd.Execute(), "convert RBAC model")
}

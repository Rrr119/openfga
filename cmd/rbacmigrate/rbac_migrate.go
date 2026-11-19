// Package rbacmigrate contains the command to migrate a classic RBAC model
// and its role assignments into an OpenFGA ReBAC model.
package rbacmigrate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openfga/openfga/pkg/migration/batchwriter"
	"github.com/openfga/openfga/pkg/migration/client"
	"github.com/openfga/openfga/pkg/migration/rbac"
	"github.com/openfga/openfga/pkg/storage"
)

// NewRBACMigrateCommand builds the `openfga rbac-migrate` CLI command.
func NewRBACMigrateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbac-migrate",
		Short: "Migrate an RBAC model and role assignments into OpenFGA ReBAC",
		Long: `Convert an RBAC specification (roles, permissions and assignments) into an
OpenFGA authorization model plus relationship tuples.

Without --api-url the command runs in dry-run mode and only writes the
generated model (and a migration report) to disk. With --api-url it uploads
the model through the existing OpenFGA REST API and batch-writes every
relationship tuple through the existing Write endpoint; no new server-side
API is required.`,
		RunE: runRBACMigrate,
		Args: cobra.NoArgs,
	}

	flags := cmd.Flags()
	flags.String(inputFlag, "", "(required) path to the RBAC spec file (JSON or YAML)")
	flags.String(apiURLFlag, "", "OpenFGA REST API base URL, e.g. http://localhost:8080; omit for dry-run")
	flags.String(storeIDFlag, "", "existing store id to migrate into; mutually exclusive with --store-name")
	flags.String(storeNameFlag, "rbac-migration", "store name to create when --store-id is not provided")
	flags.String(modelOutputFlag, "authorization-model.fga", "path to write the generated OpenFGA DSL model")
	flags.Int(batchSizeFlag, storage.DefaultMaxTuplesPerWrite, "max tuples per Write request")
	flags.Int(maxConcurrentFlag, 4, "number of Write requests in flight")
	flags.Bool(ignoreDupesFlag, false, "set on_duplicate=ignore so re-runs are idempotent")
	flags.String(apiTokenFlag, "", "optional preshared key sent as a Bearer token")

	_ = cmd.MarkFlagRequired(inputFlag)
	return cmd
}

// migrationReport is the JSON summary emitted after a migration run.
type migrationReport struct {
	StoreID              string     `json:"store_id,omitempty"`
	AuthorizationModelID string     `json:"authorization_model_id,omitempty"`
	DryRun               bool       `json:"dry_run"`
	Stats                rbac.Stats `json:"stats"`
	Warnings             []string   `json:"warnings,omitempty"`
	Batches              int        `json:"batches,omitempty"`
}

func runRBACMigrate(cmd *cobra.Command, _ []string) error {
	inputPath, err := cmd.Flags().GetString(inputFlag)
	if err != nil {
		return err
	}
	apiURL, err := cmd.Flags().GetString(apiURLFlag)
	if err != nil {
		return err
	}
	storeID, err := cmd.Flags().GetString(storeIDFlag)
	if err != nil {
		return err
	}
	storeName, err := cmd.Flags().GetString(storeNameFlag)
	if err != nil {
		return err
	}
	modelOutput, err := cmd.Flags().GetString(modelOutputFlag)
	if err != nil {
		return err
	}
	batchSize, err := cmd.Flags().GetInt(batchSizeFlag)
	if err != nil {
		return err
	}
	maxConcurrent, err := cmd.Flags().GetInt(maxConcurrentFlag)
	if err != nil {
		return err
	}
	ignoreDupes, err := cmd.Flags().GetBool(ignoreDupesFlag)
	if err != nil {
		return err
	}
	apiToken, err := cmd.Flags().GetString(apiTokenFlag)
	if err != nil {
		return err
	}

	spec, err := rbac.LoadSpec(inputPath)
	if err != nil {
		return fmt.Errorf("load RBAC spec: %w", err)
	}

	result, err := rbac.Migrate(spec)
	if err != nil {
		return fmt.Errorf("convert RBAC model: %w", err)
	}

	if err := os.WriteFile(modelOutput, []byte(result.DSL), 0o644); err != nil {
		return fmt.Errorf("write model file: %w", err)
	}
	cmd.Printf("wrote ReBAC authorization model to %s\n", modelOutput)

	for _, warning := range result.Warnings {
		cmd.Printf("warning: %s\n", warning)
	}

	report := migrationReport{
		DryRun:   apiURL == "",
		Stats:    result.Stats,
		Warnings: result.Warnings,
	}

	if apiURL == "" {
		cmd.Printf("dry-run complete: %d tuples generated, nothing was written to a server\n", result.Stats.Tuples)
		return printReport(cmd, report)
	}

	if storeID != "" && cmd.Flags().Changed(storeNameFlag) {
		return fmt.Errorf("--store-id and --store-name are mutually exclusive")
	}

	ctx := context.Background()
	apiClient := client.New(apiURL, client.WithToken(apiToken))

	if storeID == "" {
		storeID, err = apiClient.CreateStore(ctx, storeName)
		if err != nil {
			return fmt.Errorf("create store: %w", err)
		}
		cmd.Printf("created store %s\n", storeID)
	}

	modelID, err := apiClient.WriteAuthorizationModel(ctx, storeID, result.Model)
	if err != nil {
		return fmt.Errorf("write authorization model: %w", err)
	}
	cmd.Printf("wrote authorization model %s\n", modelID)

	options := []batchwriter.Option{
		batchwriter.WithBatchSize(batchSize),
		batchwriter.WithMaxConcurrentWrites(maxConcurrent),
	}
	if ignoreDupes {
		options = append(options, batchwriter.WithIgnoreDuplicates())
	}
	writer := batchwriter.New(apiClient, storeID, modelID, options...)

	writeResult, err := writer.Write(ctx, result.TupleKeys)
	if err != nil {
		return fmt.Errorf("batch write tuples: %w", err)
	}

	report.StoreID = storeID
	report.AuthorizationModelID = modelID
	report.Batches = writeResult.Batches
	cmd.Printf("wrote %d tuples in %d batches to store %s\n", writeResult.TuplesWritten, writeResult.Batches, storeID)
	return printReport(cmd, report)
}

func printReport(cmd *cobra.Command, report migrationReport) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(encoded))
	return nil
}

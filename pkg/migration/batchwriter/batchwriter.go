// Package batchwriter writes large volumes of OpenFGA relationship tuples
// through the existing Write API.
//
// OpenFGA caps a single Write request at the datastore's MaxTuplesPerWrite
// (100 by default). A BatchWriter transparently splits the input into chunks
// of that size, validates the request size up front, and drives the chunks
// with a bounded worker pool so migrations can saturate the API without
// overwhelming it. No server-side API change is involved: every chunk is a
// plain openfgav1.WriteRequest.
package batchwriter

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/pkg/storage"
)

// TupleWriter is the subset of the OpenFGA service used by BatchWriter. Both
// the in-process server (pkg/server.Server) and the generated gRPC client
// satisfy it.
type TupleWriter interface {
	Write(ctx context.Context, req *openfgav1.WriteRequest) (*openfgav1.WriteResponse, error)
}

// Option configures a BatchWriter.
type Option func(*BatchWriter)

// WithBatchSize overrides the maximum number of tuple keys sent in one Write
// request. It must be positive and no larger than the datastore limit.
func WithBatchSize(size int) Option {
	return func(w *BatchWriter) {
		w.batchSize = size
	}
}

// WithMaxConcurrentWrites sets the number of Write requests in flight. The
// default is 4. A value of 1 forces sequential, easiest-to-debug writes.
func WithMaxConcurrentWrites(n int) Option {
	return func(w *BatchWriter) {
		w.maxConcurrent = n
	}
}

// WithIgnoreDuplicates sets on_duplicate=ignore on every Write request, which
// makes re-running a migration idempotent.
func WithIgnoreDuplicates() Option {
	return func(w *BatchWriter) {
		w.ignoreDuplicates = true
	}
}

// BatchWriter streams relationship tuples into OpenFGA via the Write API.
type BatchWriter struct {
	writer               TupleWriter
	storeID              string
	authorizationModelID string
	batchSize            int
	maxConcurrent        int
	ignoreDuplicates     bool
}

// New creates a BatchWriter for a store. The authorization model id is
// attached to every Write request so tuples are validated against the model
// produced by the migration.
func New(writer TupleWriter, storeID, authorizationModelID string, opts ...Option) *BatchWriter {
	bw := &BatchWriter{
		writer:               writer,
		storeID:              storeID,
		authorizationModelID: authorizationModelID,
		batchSize:            storage.DefaultMaxTuplesPerWrite,
		maxConcurrent:        4,
	}
	for _, opt := range opts {
		opt(bw)
	}
	return bw
}

// Result reports the outcome of a batch write.
type Result struct {
	TuplesWritten int
	Batches       int
}

// Write splits tupleKeys into batches and writes them concurrently. It is
// fail-fast: the first failed request cancels the remaining batches and the
// returned error wraps the failing batch index for traceability.
func (b *BatchWriter) Write(ctx context.Context, tupleKeys []*openfgav1.TupleKey) (Result, error) {
	if len(tupleKeys) == 0 {
		return Result{}, nil
	}
	if b.batchSize <= 0 {
		return Result{}, fmt.Errorf("batch size must be positive, got %d", b.batchSize)
	}
	if b.maxConcurrent <= 0 {
		return Result{}, fmt.Errorf("max concurrent writes must be positive, got %d", b.maxConcurrent)
	}

	batches := chunkTupleKeys(tupleKeys, b.batchSize)

	var (
		mu      sync.Mutex
		written int
	)

	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(b.maxConcurrent)

	for i, batch := range batches {
		g.Go(func() error {
			req := &openfgav1.WriteRequest{
				StoreId:              b.storeID,
				AuthorizationModelId: b.authorizationModelID,
				Writes: &openfgav1.WriteRequestWrites{
					TupleKeys: batch,
				},
			}
			if b.ignoreDuplicates {
				req.Writes.OnDuplicate = "ignore"
			}

			if _, err := b.writer.Write(groupCtx, req); err != nil {
				return fmt.Errorf("write batch %d/%d (%d tuples): %w", i+1, len(batches), len(batch), err)
			}

			mu.Lock()
			written += len(batch)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return Result{TuplesWritten: written, Batches: len(batches)}, err
	}

	return Result{TuplesWritten: len(tupleKeys), Batches: len(batches)}, nil
}

// chunkTupleKeys splits tupleKeys into slices of at most batchSize.
func chunkTupleKeys(tupleKeys []*openfgav1.TupleKey, batchSize int) [][]*openfgav1.TupleKey {
	if len(tupleKeys) == 0 {
		return nil
	}
	batches := make([][]*openfgav1.TupleKey, 0, (len(tupleKeys)+batchSize-1)/batchSize)
	for start := 0; start < len(tupleKeys); start += batchSize {
		end := start + batchSize
		if end > len(tupleKeys) {
			end = len(tupleKeys)
		}
		batches = append(batches, tupleKeys[start:end])
	}
	return batches
}

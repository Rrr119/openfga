package batchwriter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/pkg/storage"
)

type fakeTupleWriter struct {
	mu          sync.Mutex
	requests    []*openfgav1.WriteRequest
	maxObserved int
	inflight    int
	failOnBatch int
	err         error
	delay       time.Duration
}

func (f *fakeTupleWriter) Write(_ context.Context, req *openfgav1.WriteRequest) (*openfgav1.WriteResponse, error) {
	f.mu.Lock()
	f.inflight++
	if f.inflight > f.maxObserved {
		f.maxObserved = f.inflight
	}
	batchIndex := len(f.requests)
	f.requests = append(f.requests, req)
	f.mu.Unlock()

	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	defer func() {
		f.mu.Lock()
		f.inflight--
		f.mu.Unlock()
	}()

	if f.err != nil && batchIndex == f.failOnBatch {
		return nil, f.err
	}
	return &openfgav1.WriteResponse{}, nil
}

func (f *fakeTupleWriter) snapshot() []*openfgav1.WriteRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*openfgav1.WriteRequest, len(f.requests))
	copy(out, f.requests)
	return out
}

func makeTupleKeys(n int) []*openfgav1.TupleKey {
	keys := make([]*openfgav1.TupleKey, n)
	for i := range keys {
		keys[i] = &openfgav1.TupleKey{
			Object:   "document:1",
			Relation: "viewer",
			User:     "user:alice",
		}
	}
	return keys
}

func TestBatchWriterChunksRequests(t *testing.T) {
	fake := &fakeTupleWriter{}
	bw := New(fake, "store-1", "model-1", WithBatchSize(10), WithMaxConcurrentWrites(1))

	result, err := bw.Write(context.Background(), makeTupleKeys(25))
	require.NoError(t, err)
	require.Equal(t, Result{TuplesWritten: 25, Batches: 3}, result)

	requests := fake.snapshot()
	require.Len(t, requests, 3)
	require.Len(t, requests[0].GetWrites().GetTupleKeys(), 10)
	require.Len(t, requests[1].GetWrites().GetTupleKeys(), 10)
	require.Len(t, requests[2].GetWrites().GetTupleKeys(), 5)

	for _, req := range requests {
		require.Equal(t, "store-1", req.GetStoreId())
		require.Equal(t, "model-1", req.GetAuthorizationModelId())
		require.Empty(t, req.GetWrites().GetOnDuplicate())
		require.Empty(t, req.GetDeletes().GetTupleKeys())
	}
}

func TestBatchWriterDefaultBatchSizeMatchesDatastoreLimit(t *testing.T) {
	fake := &fakeTupleWriter{}
	bw := New(fake, "store", "model", WithMaxConcurrentWrites(1))

	total := storage.DefaultMaxTuplesPerWrite*2 + 7
	result, err := bw.Write(context.Background(), makeTupleKeys(total))
	require.NoError(t, err)
	require.Equal(t, 3, result.Batches)
	require.Len(t, fake.snapshot()[2].GetWrites().GetTupleKeys(), 7)
}

func TestBatchWriterConcurrentRequests(t *testing.T) {
	fake := &fakeTupleWriter{delay: 5 * time.Millisecond}
	bw := New(fake, "store", "model", WithBatchSize(5), WithMaxConcurrentWrites(8))

	result, err := bw.Write(context.Background(), makeTupleKeys(200))
	require.NoError(t, err)
	require.Equal(t, 40, result.Batches)
	require.Greater(t, fake.maxObserved, 1)
	require.LessOrEqual(t, fake.maxObserved, 8)

	// Concurrency must not reorder or lose tuples.
	var seen int
	for _, req := range fake.snapshot() {
		seen += len(req.GetWrites().GetTupleKeys())
	}
	require.Equal(t, 200, seen)
}

func TestBatchWriterIgnoreDuplicates(t *testing.T) {
	fake := &fakeTupleWriter{}
	bw := New(fake, "store", "model", WithIgnoreDuplicates(), WithBatchSize(10))

	_, err := bw.Write(context.Background(), makeTupleKeys(10))
	require.NoError(t, err)
	require.Equal(t, "ignore", fake.snapshot()[0].GetWrites().GetOnDuplicate())
}

func TestBatchWriterEmptyInput(t *testing.T) {
	fake := &fakeTupleWriter{}
	bw := New(fake, "store", "model")

	result, err := bw.Write(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, Result{}, result)
	require.Empty(t, fake.snapshot())
}

func TestBatchWriterPropagatesError(t *testing.T) {
	boom := errors.New("boom")
	fake := &fakeTupleWriter{err: boom, failOnBatch: 1}
	bw := New(fake, "store", "model", WithBatchSize(10), WithMaxConcurrentWrites(1))

	_, err := bw.Write(context.Background(), makeTupleKeys(40))
	require.Error(t, err)
	require.ErrorIs(t, err, boom)
	require.ErrorContains(t, err, "write batch 2/4")
}

func TestBatchWriterRejectsBadOptions(t *testing.T) {
	fake := &fakeTupleWriter{}

	_, err := New(fake, "store", "model", WithBatchSize(0)).Write(context.Background(), makeTupleKeys(1))
	require.ErrorContains(t, err, "batch size")

	_, err = New(fake, "store", "model", WithMaxConcurrentWrites(0)).Write(context.Background(), makeTupleKeys(1))
	require.ErrorContains(t, err, "max concurrent")
}

func TestChunkTupleKeys(t *testing.T) {
	require.Nil(t, chunkTupleKeys(nil, 10))

	batches := chunkTupleKeys(makeTupleKeys(23), 10)
	require.Len(t, batches, 3)
	require.Len(t, batches[0], 10)
	require.Len(t, batches[1], 10)
	require.Len(t, batches[2], 3)
}

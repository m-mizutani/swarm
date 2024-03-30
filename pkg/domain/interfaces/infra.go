package interfaces

import (
	"context"
	"io"
	"time"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/storage"
	"github.com/m-mizutani/swarm/pkg/domain/model"
	"github.com/m-mizutani/swarm/pkg/domain/types"
)

type BigQueryIterator interface {
	Next(dst interface{}) error
}

type BigQuery interface {
	Query(ctx context.Context, query string) (BigQueryIterator, error)
	Insert(ctx context.Context, datasetID types.BQDatasetID, tableID types.BQTableID, schema bigquery.Schema, data []any) error
	GetMetadata(ctx context.Context, dataset types.BQDatasetID, table types.BQTableID) (*bigquery.TableMetadata, error)
	UpdateTable(ctx context.Context, dataset types.BQDatasetID, table types.BQTableID, md bigquery.TableMetadataToUpdate, eTag string) error
	CreateTable(ctx context.Context, dataset types.BQDatasetID, table types.BQTableID, md *bigquery.TableMetadata) error
}

type PubSub interface {
	Publish(ctx context.Context, data []byte) (types.PubSubMessageID, error)
}

type CSObjectIterator interface {
	Next() (*storage.ObjectAttrs, error)
}

type CloudStorage interface {
	Open(ctx context.Context, obj model.CloudStorageObject) (io.ReadCloser, error)
	Attrs(ctx context.Context, obj model.CloudStorageObject) (*storage.ObjectAttrs, error)
	List(ctx context.Context, bucket types.CSBucket, query *storage.Query) CSObjectIterator
}

type Database interface {
	GetOrCreateState(ctx context.Context, msgType types.MsgType, input *model.State) (*model.State, bool, error)
	GetState(ctx context.Context, msgType types.MsgType, id string) (*model.State, error)
	UpdateState(ctx context.Context, msgType types.MsgType, id string, state types.MsgState, now time.Time) error
}

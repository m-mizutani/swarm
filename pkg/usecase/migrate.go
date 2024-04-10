package usecase

import (
	"context"

	"cloud.google.com/go/bigquery"
	"github.com/m-mizutani/bqs"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/swarm/pkg/domain/model"
	"github.com/m-mizutani/swarm/pkg/domain/types"
	"github.com/m-mizutani/swarm/pkg/utils"
)

func (x *UseCase) Migrate(ctx context.Context, src, dst *model.BigQueryDest, query string) error {
	if err := x.migrateTable(ctx, src, dst); err != nil {
		return err
	}

	utils.CtxLogger(ctx).Info("migrating data", "src", src, "dst", dst, "query", query)
	if _, err := x.clients.BigQuery().Query(ctx, query); err != nil {
		return err
	}

	return nil
}

func (x *UseCase) migrateTable(ctx context.Context, src, dst *model.BigQueryDest) error {
	srcMD, err := x.clients.BigQuery().GetMetadata(ctx, src.Dataset, src.Table)
	if err != nil {
		return err
	}
	if srcMD == nil {
		return goerr.Wrap(types.ErrTableNotFound, "source table not found").With("dataset", src.Dataset).With("table", src.Table)
	}

	dstMD, err := x.clients.BigQuery().GetMetadata(ctx, dst.Dataset, dst.Table)
	if err != nil {
		return err
	}
	if dstMD == nil {
		md := &bigquery.TableMetadata{
			Schema: srcMD.Schema,
			Name:   dst.Table.String(),
			TimePartitioning: &bigquery.TimePartitioning{
				Field: "timestamp",
				Type:  dst.Partition.Type(),
			},
		}
		utils.CtxLogger(ctx).Info("creating new dst table", "dataset", dst.Dataset, "table", dst.Table)

		return x.clients.BigQuery().CreateTable(ctx, dst.Dataset, dst.Table, md)
	}

	mergedSchema, err := bqs.Merge(srcMD.Schema, dstMD.Schema)
	if err != nil {
		return goerr.Wrap(err, "can not merge schema")
	}

	if bqs.Equal(dstMD.Schema, mergedSchema) {
		utils.CtxLogger(ctx).Info("dst table exists and no need to update schema", "dataset", dst.Dataset, "table", dst.Table)
		return nil
	}

	utils.CtxLogger(ctx).Info("updating dst table schema", "dataset", dst.Dataset, "table", dst.Table)
	update := bigquery.TableMetadataToUpdate{
		Schema: mergedSchema,
	}
	if err := x.clients.BigQuery().UpdateTable(ctx, dst.Dataset, dst.Table, update, dstMD.ETag); err != nil {
		return err
	}

	return nil
}

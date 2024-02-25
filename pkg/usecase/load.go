package usecase

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/swarm/pkg/domain/interfaces"
	"github.com/m-mizutani/swarm/pkg/domain/model"
	"github.com/m-mizutani/swarm/pkg/domain/types"
	"github.com/m-mizutani/swarm/pkg/infra"
	"github.com/m-mizutani/swarm/pkg/utils"
)

func (x *UseCase) LoadDataByObject(ctx context.Context, url types.CSUrl) error {
	bucket, objID, err := url.Parse()
	if err != nil {
		return goerr.Wrap(err, "failed to parse CloudStorage URL").With("url", url)
	}

	attrs, err := x.clients.CloudStorage().Attrs(ctx, bucket, objID)
	if err != nil {
		return goerr.Wrap(err, "failed to get object attributes").With("bucket", bucket).With("objID", objID)
	}

	req := &model.LoadDataRequest{
		CSEvent: &model.CloudStorageEvent{
			Bucket:       bucket,
			Name:         objID,
			Size:         fmt.Sprintf("%d", attrs.Size),
			Etag:         attrs.Etag,
			ContentType:  attrs.ContentType,
			Generation:   fmt.Sprintf("%d", attrs.Generation),
			Kind:         "storage#object",
			Md5Hash:      string(attrs.MD5),
			MediaLink:    attrs.MediaLink,
			StorageClass: attrs.StorageClass,
			TimeCreated:  attrs.Created.Format("2006-01-02T15:04:05.999Z"),
			Updated:      attrs.Updated.Format("2006-01-02T15:04:05.999Z"),
		},
	}

	sources, err := x.EventToSources(ctx, req.CSEvent)
	if err != nil {
		return goerr.Wrap(err, "failed to convert event to sources").With("req", req)
	}

	var loadReq []*model.LoadRequest
	for _, src := range sources {
		loadReq = append(loadReq, &model.LoadRequest{
			Object: model.NewCSObject(req.CSEvent.Bucket, req.CSEvent.Name),
			Source: *src,
		})
	}

	return x.Load(ctx, loadReq)
}

func (x *UseCase) Load(ctx context.Context, requests []*model.LoadRequest) error {
	reqID, ctx := utils.CtxRequestID(ctx)

	loadLog := model.LoadLog{
		ID:        reqID,
		StartedAt: time.Now(),
	}

	if x.metadata != nil {
		schema, err := setupLoadLogTable(ctx, x.clients.BigQuery(), x.metadata)
		if err != nil {
			return err
		}

		defer func() {
			if err := x.clients.BigQuery().Insert(ctx, x.metadata.Dataset(), x.metadata.Table(), schema, []any{loadLog.Raw()}); err != nil {
				utils.HandleError(ctx, "failed to insert request log", err)
			}
		}()
	}
	defer func() {
		loadLog.FinishedAt = time.Now()
		utils.CtxLogger(ctx).Info("request handled", "req", requests, "proc.log", loadLog)
	}()

	logRecords, srcLogs, err := importLogRecords(ctx, x.clients, requests)
	loadLog.Sources = srcLogs
	if err != nil {
		loadLog.Error = err.Error()
		return err
	}

	for dst, records := range logRecords {
		log, err := ingestRecords(ctx, x.clients.BigQuery(), dst, records)
		loadLog.Ingests = append(loadLog.Ingests, log)
		if err != nil {
			loadLog.Error = err.Error()
			return err
		}
	}

	loadLog.Success = true
	return nil
}

func importLogRecords(ctx context.Context, clients *infra.Clients, requests []*model.LoadRequest) (model.LogRecordSet, []*model.SourceLog, error) {
	var logs []*model.SourceLog
	dstMap := model.LogRecordSet{}

	for _, req := range requests {
		resp, log, err := importSource(ctx, clients, req)
		if err != nil {
			return nil, logs, err
		}
		logs = append(logs, log)

		dstMap.Merge(resp)
	}

	return dstMap, logs, nil
}

func importSource(ctx context.Context, clients *infra.Clients, req *model.LoadRequest) (model.LogRecordSet, *model.SourceLog, error) {
	dstMap := model.LogRecordSet{}

	srcLog := &model.SourceLog{
		CSBucket:   req.Object.Bucket(),
		CSObjectID: req.Object.Object(),
		RowCount:   0,
		Source:     req.Source,
		StartedAt:  time.Now(),
	}
	defer func() {
		srcLog.FinishedAt = time.Now()
	}()

	rows, err := downloadCloudStorageObject(ctx, clients.CloudStorage(), req)
	if err != nil {
		return nil, srcLog, err
	}

	for _, row := range rows {
		srcLog.RowCount++

		var output model.SchemaPolicyOutput
		if err := clients.Policy().Query(ctx, req.Source.Schema.Query(), row, &output); err != nil {
			return nil, srcLog, err
		}

		if len(output.Logs) == 0 {
			utils.CtxLogger(ctx).Warn("No log data in schema policy", "req", req, "record", row)
			continue
		}

		for idx, log := range output.Logs {
			if err := log.Validate(); err != nil {
				return nil, srcLog, err
			}
			if log.ID == "" {
				log.ID = types.NewLogID(req.Object.Bucket(), req.Object.Object(), idx)
			}

			tsNano := math.Mod(log.Timestamp, 1.0) * 1000 * 1000 * 1000
			dstMap[log.BigQueryDest] = append(dstMap[log.BigQueryDest], &model.LogRecord{
				ID:         log.ID,
				Timestamp:  time.Unix(int64(log.Timestamp), int64(tsNano)),
				InsertedAt: time.Now(),

				// If there is a field that has nil value in the log.Data, the field can not be estimated field type by bqs.Infer. It will cause an error when inserting data to BigQuery. So, remove nil value from log.Data.
				Data: cloneWithoutNil(log.Data),
			})
		}
	}

	srcLog.Success = true
	return dstMap, srcLog, nil
}

func downloadCloudStorageObject(ctx context.Context, csClient interfaces.CloudStorage, req *model.LoadRequest) ([]any, error) {
	var records []any
	reader, err := csClient.Open(ctx, req.Object.Bucket(), req.Object.Object())
	if err != nil {
		return nil, goerr.Wrap(err, "failed to open object").With("req", req)
	}
	defer reader.Close()

	if req.Source.Compress == types.GZIPComp {
		r, err := gzip.NewReader(reader)
		if err != nil {
			return nil, goerr.Wrap(err, "failed to create gzip reader").With("req", req)
		}
		defer r.Close()
		reader = r
	}

	decoder := json.NewDecoder(reader)
	for decoder.More() {
		var record any
		if err := decoder.Decode(&record); err != nil {
			return nil, goerr.Wrap(err, "failed to decode JSON").With("req", req)
		}

		records = append(records, record)
	}

	return records, nil
}

func ingestRecords(ctx context.Context, bq interfaces.BigQuery, bqDst model.BigQueryDest, records []*model.LogRecord) (*model.IngestLog, error) {
	ingestID, ctx := utils.CtxIngestID(ctx)

	result := &model.IngestLog{
		ID:        ingestID,
		StartedAt: time.Now(),
		DatasetID: bqDst.Dataset,
		TableID:   bqDst.Table,
		LogCount:  len(records),
	}

	defer func() {
		result.FinishedAt = time.Now()
	}()

	schema, err := inferSchema(records)
	if err != nil {
		return result, err
	}

	md := &bigquery.TableMetadata{
		Schema: schema,
	}

	tpMap := map[types.BQPartition]bigquery.TimePartitioningType{
		types.BQPartitionHour:  bigquery.HourPartitioningType,
		types.BQPartitionDay:   bigquery.DayPartitioningType,
		types.BQPartitionMonth: bigquery.MonthPartitioningType,
		types.BQPartitionYear:  bigquery.YearPartitioningType,
	}
	if bqDst.Partition != "" {
		if t, ok := tpMap[bqDst.Partition]; ok {
			md.TimePartitioning = &bigquery.TimePartitioning{
				Field: "Timestamp",
				Type:  t,
			}
		} else {
			return result, goerr.Wrap(types.ErrInvalidPolicyResult, "invalid time unit").With("Partition", bqDst.Partition)
		}
	}

	finalized, err := createOrUpdateTable(ctx, bq, bqDst.Dataset, bqDst.Table, md)
	if err != nil {
		return result, goerr.Wrap(err, "failed to update schema").With("dst", bqDst)
	}

	jsonSchema, err := schemaToJSON(schema)
	if err != nil {
		return result, err
	}
	result.TableSchema = string(jsonSchema)

	data := make([]any, len(records))
	for i := range records {
		records[i].IngestID = ingestID
		data[i] = records[i].Raw()
	}

	if err := bq.Insert(ctx, bqDst.Dataset, bqDst.Table, finalized, data); err != nil {
		return result, goerr.Wrap(err, "failed to insert data").With("dst", bqDst)
	}

	result.Success = true
	return result, nil
}

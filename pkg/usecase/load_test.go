package usecase_test

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/swarm/pkg/domain/model"
	"github.com/m-mizutani/swarm/pkg/domain/types"
	"github.com/m-mizutani/swarm/pkg/infra"
	"github.com/m-mizutani/swarm/pkg/infra/bq"
	"github.com/m-mizutani/swarm/pkg/infra/cs"
	"github.com/m-mizutani/swarm/pkg/infra/policy"
	"github.com/m-mizutani/swarm/pkg/usecase"
	"github.com/m-mizutani/swarm/pkg/utils"
)

func TestLoadDataByObject(t *testing.T) {
	bqProject := utils.LoadEnv(t, "TEST_BIGQUERY_PROJECT_ID")
	bqDataset := utils.LoadEnv(t, "TEST_BIGQUERY_DATASET_ID")
	tableID := utils.LoadEnv(t, "TEST_BIGQUERY_TABLE_ID")
	gcsURL := utils.LoadEnv(t, "TEST_GCS_OBJECT_URL")
	policyDir := utils.LoadEnv(t, "TEST_POLICY_DIR")

	ctx := context.Background()
	bqClient := gt.R1(bq.New(ctx, bqProject)).NoError(t)
	csClient := gt.R1(cs.New(ctx)).NoError(t)
	pClient := gt.R1(policy.New(policy.WithDir(policyDir))).NoError(t)
	meta := model.NewMetadataConfig(types.BQDatasetID(bqDataset), types.BQTableID(tableID))

	uc := usecase.New(
		infra.New(
			infra.WithBigQuery(bqClient),
			infra.WithCloudStorage(csClient),
			infra.WithPolicy(pClient),
		),
		usecase.WithMetadata(meta),
	)

	gt.NoError(t, uc.LoadDataByObject(ctx, types.CSUrl(gcsURL)))
}

//go:embed testdata/object/cloudtrail_example.json
var cloudTrailExampleRaw []byte

//go:embed testdata/object/cloudtrail_example.json.gz
var cloudTrailExampleGzip []byte

func TestLoadData(t *testing.T) {
	testCases := map[string]struct {
		objectName types.CSObjectID
		objectData []byte
		model.Source
	}{
		"cloudtrail_example.json": {
			objectName: "cloudtrail_example.log",
			objectData: cloudTrailExampleRaw,
			Source: model.Source{
				Parser:   types.JSONParser,
				Schema:   "cloudtrail",
				Compress: types.NoCompress,
			},
		},
		"cloudtrail_example.json.gz": {
			objectName: "cloudtrail_example.log.gz",
			objectData: cloudTrailExampleGzip,
			Source: model.Source{
				Parser:   types.JSONParser,
				Schema:   "cloudtrail",
				Compress: types.GZIPComp,
			},
		},
	}

	for label, tc := range testCases {
		t.Run(label, func(t *testing.T) {
			ctx := context.Background()
			bqClient := bq.NewGeneralMock()
			csClient := &cs.Mock{
				MockOpen: func(ctx context.Context, obj model.CloudStorageObject) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader([]byte(tc.objectData))), nil
				},
			}
			pClient := gt.R1(policy.New(policy.WithDir("testdata/policy"))).NoError(t)
			meta := model.NewMetadataConfig("test-dataset", "test-table")

			uc := usecase.New(
				infra.New(
					infra.WithBigQuery(bqClient),
					infra.WithCloudStorage(csClient),
					infra.WithPolicy(pClient),
				),
				usecase.WithMetadata(meta),
			)

			req := &model.LoadRequest{
				Source: tc.Source,
				Object: model.Object{
					CS: &model.CloudStorageObject{
						Bucket: "test-bucket",
						Name:   tc.objectName,
					},
				},
			}

			gt.NoError(t, uc.Load(ctx, []*model.LoadRequest{req}))

			ids := []types.LogID{
				"ac3cfd93-435d-41cc-bbd7-aad0340ec668",
				"18e67b09-94a3-4b5c-9b3a-cd549b3341fb",
				"dbb28938-5ed4-4774-8bb6-82ea916b21bb",
				"d4dacb9d-9822-4217-b88d-d334bde89755",
			}
			gt.A(t, bqClient.Inserted).Length(2)
			gt.A(t, bqClient.Inserted[0].Data).Length(4)
			for i, id := range ids {
				r := gt.Cast[*model.LogRecordRaw](t, bqClient.Inserted[0].Data[i])
				gt.Equal(t, r.ID, id)
			}
		})
	}
}

func TestIngestRecordBigNum(t *testing.T) {
	bqMock := bq.NewGeneralMock()
	ctx := context.Background()
	dst := model.BigQueryDest{
		Dataset: "test-dataset",
		Table:   "test-table",
	}

	var records []*model.LogRecord
	for i := 0; i < 1001; i++ {
		records = append(records, &model.LogRecord{
			ID:        types.LogID(uuid.NewString()),
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"key": "value",
			},
			IngestedAt: time.Now(),
		})
	}

	resp := gt.R1(usecase.IngestRecords(ctx, bqMock, dst, records, 10)).NoError(t)
	gt.True(t, resp.Success)

	gt.A(t, bqMock.Inserted).Length(4)
	c256, c233 := 0, 0
	for _, r := range bqMock.Inserted {
		if len(r.Data) == 256 {
			c256++
		} else if len(r.Data) == 233 {
			c233++
		} else {
			t.Errorf("Unexpected data length: %d", len(r.Data))
		}
	}
	gt.N(t, c256).Equal(3)
	gt.N(t, c233).Equal(1)
}

package server_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/swarm/pkg/controller/server"
	"github.com/m-mizutani/swarm/pkg/domain/model"
	"github.com/m-mizutani/swarm/pkg/infra"
	"github.com/m-mizutani/swarm/pkg/infra/policy"
	"github.com/m-mizutani/swarm/pkg/usecase"
)

func TestAuthorization(t *testing.T) {
	p := gt.R1(policy.New(
		policy.WithFile("testdata/policy/auth_token.rego"),
	)).NoError(t)
	uc := usecase.New(infra.New(infra.WithPolicy(p)))
	mock := &usecase.Mock{
		MockAuthorize: func(ctx context.Context, input *model.AuthPolicyInput) error {
			return uc.Authorize(ctx, input)
		},
	}

	srv := server.New(mock)

	testCases := map[string]struct {
		token string
		code  int
	}{
		"Allow": {
			token: "good-token",
			code:  http.StatusOK,
		},
		"Deny": {
			token: "bad-token",
			code:  http.StatusUnauthorized,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/event/pubsub/cs", strings.NewReader(string(pubsubBody)))
			r.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			gt.Equal(t, w.Code, tc.code)
		})
	}
}

func TestMemoryLimit(t *testing.T) {
	mock := &usecase.Mock{}

	var currentMem uint64 = 100
	readMemMock := func(m *runtime.MemStats) {
		m.HeapAlloc = currentMem
	}
	srv := server.New(mock, server.WithMemoryLimit(1000), server.WithReadMemStats(readMemMock))

	t.Run("not reach to memory limit", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/event/pubsub/cs", bytes.NewReader(pubsubBody))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		gt.Equal(t, w.Code, http.StatusOK)
	})

	t.Run("reached memory limit", func(t *testing.T) {
		currentMem = 1001
		r := httptest.NewRequest("POST", "/event/pubsub/cs", bytes.NewReader(pubsubBody))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		gt.Equal(t, w.Code, http.StatusTooManyRequests)
	})
}

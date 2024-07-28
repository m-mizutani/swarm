package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"

	"github.com/go-chi/chi/v5"
	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/swarm/pkg/domain/interfaces"
	"github.com/m-mizutani/swarm/pkg/domain/model"
	"github.com/m-mizutani/swarm/pkg/domain/types"
	"github.com/m-mizutani/swarm/pkg/utils"
)

type Server struct {
	mux *chi.Mux
}

type serverCfg struct {
	memoryLimit uint64
	readMem     ReadMemStatsFn
}

type requestHandler func(uc interfaces.UseCase, r *http.Request) error

type Option func(*serverCfg)

func WithMemoryLimit(limit uint64) Option {
	return func(cfg *serverCfg) {
		cfg.memoryLimit = limit
	}
}

func WithReadMemStats(fn ReadMemStatsFn) Option {
	return func(cfg *serverCfg) {
		cfg.readMem = fn
	}
}

func New(uc interfaces.UseCase, options ...Option) *Server {
	cfg := &serverCfg{
		memoryLimit: 0,
		readMem:     runtime.ReadMemStats,
	}
	for _, opt := range options {
		opt(cfg)
	}

	route := chi.NewRouter()

	route.Use(Logging)
	route.Use(Authorization(uc))

	route.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		utils.SafeWrite(w, []byte("OK"))
	})

	api := func(f requestHandler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := f(uc, r); err != nil {
				// Google Cloud PubSub has ack deadline configuration.
				// Details: https://cloud.google.com/pubsub/docs/lease-management
				// The maximum ack deadline is 600 seconds (10 minutes). If the ack deadline is exceeded, the message is redelivered. Then we should return 205 Reset Content to PubSub to avoid redelivery until the process is working correctly.
				// PubSub can accepts 102, 200, 201, 202 and 204 as success status code.
				// https://cloud.google.com/pubsub/docs/push#receive_push
				// Then, we should return 205 Reset Content to PubSub for redelivery after the ack deadline is exceeded.
				if errors.Is(err, types.ErrBlockingPubSub) {
					http.Error(w, err.Error(), http.StatusResetContent)
					return
				}

				if errors.Is(err, types.ErrStateWaitTimeout) {
					http.Error(w, err.Error(), http.StatusTooManyRequests)
					return
				}

				utils.HandleError(r.Context(), "failed handle event", err)
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}

			w.WriteHeader(http.StatusOK)
			utils.SafeWrite(w, []byte("OK"))
		}
	}

	route.Route("/event", func(r chi.Router) {
		if cfg.memoryLimit > 0 {
			r.Use(MemoryLimit(cfg.memoryLimit, cfg.readMem))
		}

		r.Route("/pubsub", func(r chi.Router) {
			r.Post("/cs", api(handlePubSubMessage(handleCloudStorageEvent)))
			r.Post("/swarm", api(handlePubSubMessage(handleSwarmEvent)))
		})
	})

	return &Server{
		mux: route,
	}
}

type eventHandler func(ctx context.Context, uc interfaces.UseCase, data []byte) error

func handlePubSubMessage(hdlr eventHandler) requestHandler {
	return func(uc interfaces.UseCase, r *http.Request) error {
		var msg model.PubSubBody
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return goerr.Wrap(err, "failed to read body")
		}
		if err := json.Unmarshal(body, &msg); err != nil {
			return goerr.Wrap(err, "failed to unmarshal body").With("body", string(body))
		}

		ctx := r.Context()
		utils.CtxLogger(ctx).Info("Received pubsub message", "pubsub_msg", msg)

		if state, acquired, err := uc.GetOrCreateState(ctx, types.MsgPubSub, msg.Message.MessageID); err != nil {
			return goerr.Wrap(err, "failed to get or create state for pubsub")
		} else if !acquired {
			if state.State == types.MsgCompleted {
				utils.CtxLogger(ctx).Info("skip pubsub message because it's already completed", "pubsub_msg", msg)
				return nil
			}

			utils.CtxLogger(ctx).Info(
				"skip pubsub message because it's already acquired, but need to sleep",
				"pubsub_msg", msg,
			)

			if err := uc.WaitState(ctx, types.MsgPubSub, msg.Message.MessageID, state.ExpiresAt); err != nil {
				return goerr.Wrap(err, "failed to wait state")
			}

			return types.ErrBlockingPubSub
		}

		msgState := types.MsgFailed
		defer func() {
			if err := uc.UpdateState(ctx, types.MsgPubSub, msg.Message.MessageID, msgState); err != nil {
				utils.HandleError(ctx, "failed to update state", err)
			}
		}()

		data, err := base64.StdEncoding.DecodeString(msg.Message.Data)
		if err != nil {
			return goerr.Wrap(err, "failed to decode base64").With("data", msg.Message.Data)
		}

		if err := hdlr(ctx, uc, data); err != nil {
			return goerr.Wrap(err, "failed to handle pubsub message")
		}
		msgState = types.MsgCompleted

		return nil
	}
}

func (x *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	x.mux.ServeHTTP(w, r)
}

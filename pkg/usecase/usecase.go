package usecase

import (
	"time"

	"github.com/m-mizutani/swarm/pkg/domain/model"
	"github.com/m-mizutani/swarm/pkg/infra"
)

type UseCase struct {
	clients  *infra.Clients
	metadata *model.MetadataConfig

	readObjectConcurrency   int
	ingestTableConcurrency  int
	ingestRecordConcurrency int
	enqueueCountLimit       int
	enqueueSizeLimit        int

	// stateTimeout is a duration to wait for state transition. Even if the state is not changed, other process can acquire the state after this duration.
	stateTimeout time.Duration

	// stateTTL is a duration to keep the state. After this duration, the state is deleted from database. This is used to avoid re-process of the same message.
	stateTTL time.Duration

	// stateCheckInterval is a duration to check state transition. This is used in WaitState method.
	stateCheckInterval time.Duration

	// stateWaitTimeout is a duration to wait for state transition. This is used in WaitState method.
	stateWaitTimeout time.Duration
}

const (
	defaultReadObjectConcurrency   = 32
	defaultEnqueueCountLimit       = 128
	defaultEnqueueSizeLimit        = 4 // MiB
	defaultIngestTableConcurrency  = 8
	defaultIngestRecordConcurrency = 8
	defaultStateTimeout            = 30 * time.Minute
	defaultStateTTL                = 7 * 24 * time.Hour
	defaultStateCheckInterval      = 10 * time.Second
	defaultStateWaitTimeout        = 2 * time.Minute
)

func New(clients *infra.Clients, options ...Option) *UseCase {
	uc := &UseCase{
		clients:                 clients,
		readObjectConcurrency:   defaultReadObjectConcurrency,
		ingestTableConcurrency:  defaultIngestTableConcurrency,
		ingestRecordConcurrency: defaultIngestRecordConcurrency,
		enqueueCountLimit:       defaultEnqueueCountLimit,
		enqueueSizeLimit:        defaultEnqueueSizeLimit,
		stateTimeout:            defaultStateTimeout,
		stateTTL:                defaultStateTTL,
		stateCheckInterval:      defaultStateCheckInterval,
		stateWaitTimeout:        defaultStateWaitTimeout,
	}

	for _, option := range options {
		option(uc)
	}

	return uc
}

type Option func(*UseCase)

func WithMetadata(metadata *model.MetadataConfig) Option {
	return func(uc *UseCase) {
		uc.metadata = metadata
	}
}

func WithReadObjectConcurrency(n int) Option {
	if n < 1 {
		n = 1
	}
	return func(uc *UseCase) {
		uc.readObjectConcurrency = n
	}
}

func WithEnqueueCountLimit(n int) Option {
	if n < 1 {
		n = 1
	}
	return func(uc *UseCase) {
		uc.enqueueCountLimit = n
	}
}

func WithEnqueueSizeLimit(n int) Option {
	if n < 1 {
		n = 1
	}
	return func(uc *UseCase) {
		uc.enqueueSizeLimit = n
	}
}

func WithIngestTableConcurrency(n int) Option {
	if n < 1 {
		n = 1
	}
	return func(uc *UseCase) {
		uc.ingestTableConcurrency = n
	}
}

func WithIngestRecordConcurrency(n int) Option {
	if n < 1 {
		n = 1
	}
	return func(uc *UseCase) {
		uc.ingestRecordConcurrency = n
	}
}

func WithStateTimeout(d time.Duration) Option {
	return func(uc *UseCase) {
		uc.stateTimeout = d
	}
}

func WithStateTTL(d time.Duration) Option {
	return func(uc *UseCase) {
		uc.stateTTL = d
	}
}

func WithStateCheckInterval(d time.Duration) Option {
	return func(uc *UseCase) {
		uc.stateCheckInterval = d
	}
}

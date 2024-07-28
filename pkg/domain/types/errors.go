package types

import "github.com/m-mizutani/goerr"

var (
	ErrInvalidOption = goerr.New("invalid option")

	// Bad request
	ErrUnauthorized   = goerr.New("unauthorized")
	ErrInvalidRequest = goerr.New("invalid request")

	// Configuration error
	ErrNoSourceMatched = goerr.New("no source matched")
	ErrNoPolicyData    = goerr.New("no policy data")

	// Runtime error
	ErrDataInsertion       = goerr.New("failed to insert data to bigquery")
	ErrNoPolicyResult      = goerr.New("no policy result")
	ErrInvalidPolicyResult = goerr.New("invalid policy result")
	ErrStateNotFound       = goerr.New("state not found")
	ErrTableNotFound       = goerr.New("table not found")

	// Assertion error
	ErrAssertion = goerr.New("assertion error")

	// Normal error
	ErrBlockingPubSub   = goerr.New("blocking pubsub ack")
	ErrSchemaNotMatched = goerr.New("schema not matched")

	// State error
	ErrStateWaitTimeout = goerr.New("state wait timeout")
)

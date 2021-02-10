package credentials

import (
	"context"
)

// JWTSource is the interface Provider uses to fetch JWTs.
type JWTSource interface {
	// FetchToken returns a token
	FetchToken(ctx context.Context) (string, error)
}

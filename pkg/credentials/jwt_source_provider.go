package credentials

import (
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type JWTSourceProvider func(
	subject spiffeid.ID,
	workloadSocket string,
	audience string,
	logger logger.Logger) JWTSource

func StandardJWTSourceProvider(
	subject spiffeid.ID,
	workloadSocket string,
	audience string,
	logger logger.Logger) JWTSource {

	return NewJWTSVIDSource(subject, workloadSocket, audience, logger)
}

func StaticJWTSourceProvider(source JWTSource) func(spiffeid.ID, string, string, logger.Logger) JWTSource {
	return func(spiffeid.ID, string, string, logger.Logger) JWTSource {
		return source
	}
}

package credentials

import (
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
)

type JWTSourceProvider func(
	subject spiffeid.ID,
	workloadSocket string,
	audience string,
	logger logger.Logger,
	telemetry *telemetry.Telemetry) JWTSource

func StandardJWTSourceProvider(
	subject spiffeid.ID,
	workloadSocket string,
	audience string,
	logger logger.Logger,
	telemetry *telemetry.Telemetry) JWTSource {

	return NewJWTSVIDSource(subject, workloadSocket, audience, logger, telemetry)
}

func StaticJWTSourceProvider(source JWTSource) func(
	spiffeid.ID,
	string, string,
	logger.Logger,
	*telemetry.Telemetry) JWTSource {

	return func(spiffeid.ID, string, string, logger.Logger, *telemetry.Telemetry) JWTSource {
		return source
	}
}

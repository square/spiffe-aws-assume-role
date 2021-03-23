package cli

import (
	"github.com/sirupsen/logrus"
	"github.com/square/spiffe-aws-assume-role/pkg/credentials"
	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
)

type CliContext struct {
	JWTSourceProvider credentials.JWTSourceProvider
	STSProvider       credentials.STSProvider
	Logger            *logrus.Logger
	Telemetry         *telemetry.Telemetry
}

func NewDefaultCliContext() (*CliContext, error) {
	logger := logrus.New()
	// Example log line:
	// time="2021-03-01T16:28:51-08:00" level=error msg="failed to parse SPIFFE ID from 305d07ed-765e-4642-9bd3-4c74aa86f5ed: spiffeid: invalid scheme"
	logger.SetFormatter(&logrus.TextFormatter{})

	telemetry, err := telemetry.NullTelemetry()
	if err != nil {
		return nil, err
	}

	context := &CliContext{
		JWTSourceProvider: credentials.StandardJWTSourceProvider,
		STSProvider:       credentials.StandardSTSProvider,
		Logger:            logger,
		Telemetry:         telemetry,
	}

	return context, nil
}

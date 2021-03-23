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

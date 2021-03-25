package cli

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/square/spiffe-aws-assume-role/cmd/spiffe-aws-assume-role/cli/mappers"
	"github.com/square/spiffe-aws-assume-role/pkg/credentials"
	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
)

type CLI struct {
	Credentials CredentialsCmd `kong:"cmd,help:'print credentials in a format usable as an AWS credentials_process'"`
}

func RunWithDefaultContext(args []string) error {
	logger := logrus.New()
	// Example log line:
	// time="2021-03-01T16:28:51-08:00" level=error msg="failed to parse SPIFFE ID from 305d07ed-765e-4642-9bd3-4c74aa86f5ed: spiffeid: invalid scheme"
	logger.SetFormatter(&logrus.TextFormatter{})

	telemetry, err := telemetry.NullTelemetry()
	if err != nil {
		return err
	}

	context := &CliContext{
		JWTSourceProvider: credentials.StandardJWTSourceProvider,
		STSProvider:       credentials.StandardSTSProvider,
		Logger:            logger,
		Telemetry:         telemetry,
	}

	return Run(context, args)
}

func Run(context *CliContext, args []string) (err error) {
	defer func() {
		if err != nil {
			context.Logger.Error(err)
		}
	}()

	ctx, err := parse(args)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to parse command line arguments: %s", args))
	}

	err = ctx.Run(context)

	return err
}

func newKong(cli *CLI) (*kong.Kong, error) {
	return kong.New(cli, kong.NamedMapper(mappers.Iso8601DurationMapperType, mappers.Iso8601DurationMapper{}))
}

func parse(args []string) (*kong.Context, error) {
	parser, err := newKong(&CLI{})
	if err != nil {
		return nil, err
	}

	return parser.Parse(args)
}

func createSession(stsEndpoint string, stsRegion string) *session.Session {
	config := &aws.Config{}

	if len(stsEndpoint) > 0 {
		config.Endpoint = aws.String(stsEndpoint)
	}

	if len(stsRegion) > 0 {
		config.Region = aws.String(stsRegion)
	}

	return session.Must(session.NewSession(config))
}

package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/square/spiffe-aws-assume-role/cmd/spiffe-aws-assume-role/cli/mappers"
	"github.com/square/spiffe-aws-assume-role/pkg/credentials"
	"github.com/square/spiffe-aws-assume-role/pkg/processcreds"
)

type CredentialsCmd struct {
	Audience        string        `required:"" help:"SVID JWT Audience. Must match AWS configuration"`
	SpiffeID        string        `required:"" help:"The SPIFFE ID of this workload"`
	WorkloadSocket  string        `optional:"" help:"Path to SPIFFE Workload Socket"`
	RoleARN         string        `required:"" help:"AWS Role ARN to assume"`
	SessionName     string        `optional:"" help:"AWS Session Name"`
	STSEndpoint     string        `optional:"" help:"AWS STS Endpoint"`
	STSRegion       string        `optional:"" help:"AWS STS Region"`
	SessionDuration time.Duration `optional:"" type:"iso8601duration" help:"AWS session duration in ISO8601 duration format (e.g. PT5M for five minutes)"`
	LogFilePath     string        `optional:"" help:"Path to log file"`
}

type CliContext struct {
	JWTSourceProvider credentials.JWTSourceProvider
	STSProvider       credentials.STSProvider
	Logger            *logrus.Logger
}

func (c *CredentialsCmd) Run(context *CliContext) error {
	c.configureLogger(context.Logger)

	spiffeID, err := spiffeid.FromString(c.SpiffeID)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to parse SPIFFE ID from %s", c.SpiffeID))
	}

	src := context.JWTSourceProvider(spiffeID, c.WorkloadSocket, c.Audience, context.Logger)

	session := createSession(c.STSEndpoint, c.STSRegion)
	stsClient := context.STSProvider(session)

	provider, err := credentials.NewProvider(
		c.Audience,
		c.RoleARN,
		src,
		c.SessionDuration,
		stsClient)
	if err != nil {
		return errors.Wrap(err, "failed to instantiate credentials provider")
	}

	creds, err := processcreds.SerializeCredentials(provider)
	if err != nil {
		return errors.Wrap(err, "failed to serialize credentials")
	}

	_, err = fmt.Print(string(creds))
	return err
}

func (c *CredentialsCmd) configureLogger(logger *logrus.Logger) {
	if len(c.LogFilePath) > 0 {
		file, err := os.OpenFile(c.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.Info(errors.Wrapf(err, "Failed to log to file %s, using default of stderr", c.LogFilePath))
		} else {
			logger.Out = io.MultiWriter(os.Stderr, file)
		}
	}
}

type CLI struct {
	Credentials CredentialsCmd `kong:"cmd,help:'print credentials in a format usable as an AWS credentials_process'"`
}

func RunWithDefaultContext(args []string) error {
	logger := logrus.New()
	// Example log line:
	// time="2021-03-01T16:28:51-08:00" level=error msg="failed to parse SPIFFE ID from 305d07ed-765e-4642-9bd3-4c74aa86f5ed: spiffeid: invalid scheme"
	logger.SetFormatter(&logrus.TextFormatter{})

	context := &CliContext{
		JWTSourceProvider: credentials.StandardJWTSourceProvider,
		STSProvider:       credentials.StandardSTSProvider,
		Logger:            logger,
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

func createLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{})

	file, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logger.Info(errors.Wrapf(err, "Failed to log to file %s, using default of stderr", logFileName))
	} else {
		logger.Out = io.MultiWriter(os.Stderr, file)
	}

	return logger
}

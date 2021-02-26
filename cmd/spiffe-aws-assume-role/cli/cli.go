package cli

import (
	"fmt"
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

const (
	logFileName = "spiffe-aws-assume-role.log"
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
}

type CliContext struct {
	JWTSourceProvider credentials.JWTSourceProvider
	STSProvider       credentials.STSProvider
}

func (c *CredentialsCmd) Run(context *CliContext) error {
	spiffeID, err := spiffeid.FromString(c.SpiffeID)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to parse SPIFFE ID from %s", c.SpiffeID))
	}

	src := context.JWTSourceProvider(spiffeID, c.WorkloadSocket, c.Audience)

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

type CLI struct {
	Credentials CredentialsCmd `kong:"cmd,help:'print credentials in a format usable as an AWS credentials_process'"`
}

func RunWithDefaultContext(args []string) error {
	context := &CliContext{
		JWTSourceProvider: credentials.StandardJWTSourceProvider,
		STSProvider:       credentials.StandardSTSProvider,
	}

	return Run(context, args)
}

func Run(context *CliContext, args []string) error {
	err := doRun(context, args)
	if err != nil {
		logger := createLogger()
		logger.Error(err)
	}

	return err
}

func doRun(context *CliContext, args []string) error {
	ctx, err := parse(args)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to parse command line arguments: %s", args))
	}

	if err = ctx.Run(context); err != nil {
		return err
	}

	return nil
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
		logger.Out = os.Stdout
		logger.Info("Failed to log to file, using default of stdout")
	} else {
		logger.Out = file
	}

	return logger
}

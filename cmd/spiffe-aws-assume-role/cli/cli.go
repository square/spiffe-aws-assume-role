package cli

import (
	"fmt"
	"time"

	"github.com/alecthomas/kong"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/square/spiffe-aws-assume-role/cmd/spiffe-aws-assume-role/cli/mappers"
	"github.com/square/spiffe-aws-assume-role/pkg/credentials"
	"github.com/square/spiffe-aws-assume-role/pkg/processcreds"
)

type CredentialsCmd struct {
	Audience        string        `required help:"SVID JWT Audience. Must match AWS configuration"`
	SpiffeID        string        `required help:"The SPIFFE ID of this workload"`
	WorkloadSocket  string        `optional help:"Path to SPIFFE Workload Socket"`
	RoleARN         string        `required help:"AWS Role ARN to assume"`
	SessionName     string        `optional help:"AWS Session Name"`
	STSEndpoint     string        `optional help:"AWS STS Endpoint variable"`
	SessionDuration time.Duration `optional type:iso8601duration help:"AWS session duration in ISO8601 duration format (e.g. PT5M for five minutes)"`
}

type CliContext struct {
	JWTSourceProvider credentials.JWTSourceProvider
	STSProvider       credentials.STSProvider
}

func (c *CredentialsCmd) Run(context *CliContext) error {
	spiffeID, err := spiffeid.FromString(c.SpiffeID)
	if err != nil {
		return err
	}

	src := context.JWTSourceProvider(spiffeID, c.WorkloadSocket, c.Audience)

	provider, err := credentials.NewProvider(
		c.Audience,
		c.RoleARN,
		src,
		c.SessionDuration,
		context.STSProvider)
	if err != nil {
		return err
	}

	creds, err := processcreds.SerializeCredentials(provider)
	if err != nil {
		return err
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
	ctx, err := parse(args)
	if err != nil {
		return err
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

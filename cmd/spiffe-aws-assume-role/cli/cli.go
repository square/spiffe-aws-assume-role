package cli

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/pkg/errors"
	"github.com/square/spiffe-aws-assume-role/cmd/spiffe-aws-assume-role/cli/mappers"
)

type CLI struct {
	Credentials CredentialsCmd `kong:"cmd,help:'print credentials in a format usable as an AWS credentials_process'"`
}

func RunWithDefaultContext(args []string) error {
	context, err := NewDefaultCliContext()
	if err != nil {
		return err
	}

	return Run(context, args)
}

func Run(context *CliContext, args []string) (err error) {
	defer func() {
		if err != nil {
			context.Logger.Error(err)
		}
	}()

	ctx, err := Parse(args)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to parse command line arguments: %s", args))
	}

	err = ctx.Run(context)

	return err
}

func newKong(cli *CLI) (*kong.Kong, error) {
	return kong.New(cli, kong.NamedMapper(mappers.Iso8601DurationMapperType, mappers.Iso8601DurationMapper{}))
}

func Parse(args []string) (*kong.Context, error) {
	parser, err := newKong(&CLI{})
	if err != nil {
		return nil, err
	}

	return parser.Parse(args)
}

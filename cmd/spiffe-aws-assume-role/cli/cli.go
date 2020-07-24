package cli

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/square/spiffe-aws-assume-role/pkg/credentials"
	"github.com/square/spiffe-aws-assume-role/pkg/processcreds"
)

type CredentialsCmd struct {
	Audience       string `required:"" help:"SVID JWT Audience. Must match AWS configuration"`
	SpiffeID       string `required:"" help:"The SPIFFE ID of this workload"`
	WorkloadSocket string `optional:"" help:"Path to SPIFFE Workload Socket" type:"existingfile"`
	RoleARN        string `required:"" help:"AWS Role ARN to assume"`
	SessionName    string `optional:"" help:"AWS Session Name"`
	STSEndpoint    string `optional:"" help:"AWS STS Endpoint variable"`
}

func (c *CredentialsCmd) Run() error {
	spiffeID, err := spiffeid.FromString(c.SpiffeID)
	if err != nil {
		return err
	}

	src := credentials.NewJWTSVIDSource(spiffeID, c.WorkloadSocket, c.Audience)

	provider, err := credentials.NewProvider(c.Audience, src)
	if err != nil {
		return err
	}

	creds, err := processcreds.SerializeCredentials(provider)
	if err != nil {
		return err
	}

	_, err = fmt.Print(creds)
	return err
}

var CLI struct {
	Credentials CredentialsCmd `kong:"cmd,help:'print credentials in a format usable as an AWS credentials_process'"`
}

func Run(args []string) error {
	p, err := kong.New(&CLI)
	if err != nil {
		return err
	}

	ctx, err := p.Parse(args)
	if err != nil {
		return err
	}

	if err = ctx.Run(); err != nil {
		return err
	}

	return nil
}

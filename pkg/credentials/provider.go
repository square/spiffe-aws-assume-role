package credentials

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

// JWTSource is the interface this provider uses to fetch JWTs.
type JWTSource interface {
	// FetchToken returns a token
	FetchToken(ctx context.Context) (string, error)
}

func NewProvider(audience string, jwtSource JWTSource) (*Provider, error) {
	cfg := Provider{
		Expiry:      credentials.Expiry{},
		stsClient:   nil, // TODO: Need to set up AWS STS client
		audience:    audience,
		RenewWindow: time.Minute, // Default to 1 minute pre-renew. This avoids in-flight requests expiring.
		jwtSource:   jwtSource,
	}

	return &cfg, nil
}

type Provider struct {
	credentials.Expiry

	stsClient *sts.STS
	jwtSource JWTSource

	audience string

	Policy      string
	RoleARN     string
	SessionName string
	PolicyARNs  []string

	SessionDuration time.Duration
	RenewWindow     time.Duration
}

// SpiffeProvider implements the AWS credentials Provider interface
var _ credentials.Provider = &Provider{}

// Retrieve returns a set of credentials to use.
func (sp *Provider) Retrieve() (credentials.Value, error) {
	ctx := context.Background()

	token, err := sp.jwtSource.FetchToken(ctx)
	if err != nil {
		return credentials.Value{}, err
	}

	out, err := sp.assumeRole(ctx, token)
	if err != nil {
		return credentials.Value{}, err
	}

	sp.Expiry.SetExpiration(*out.Credentials.Expiration, sp.RenewWindow)

	return credentials.Value{
		AccessKeyID:     *out.Credentials.AccessKeyId,
		SecretAccessKey: *out.Credentials.SecretAccessKey,
		SessionToken:    *out.Credentials.SessionToken,
		ProviderName:    "not sure what this is for!",
	}, nil
}

func (sp *Provider) assumeRole(ctx context.Context, token string) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	assumeReq := sts.AssumeRoleWithWebIdentityInput{
		Policy:           &sp.Policy,
		RoleArn:          &sp.RoleARN,
		RoleSessionName:  &sp.SessionName,
		WebIdentityToken: &token,
	}

	if sp.SessionDuration != 0 {
		assumeReq.DurationSeconds = aws.Int64(int64(sp.SessionDuration.Seconds()))
	}

	if *assumeReq.RoleSessionName == "" {
		assumeReq.RoleSessionName = aws.String("session name from provider.go")
	}

	for _, arn := range sp.PolicyARNs {
		assumeReq.PolicyArns = append(assumeReq.PolicyArns, &sts.PolicyDescriptorType{Arn: aws.String(arn)})
	}

	return sp.stsClient.AssumeRoleWithWebIdentityWithContext(ctx, &assumeReq)
}

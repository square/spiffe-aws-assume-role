package credentials

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

func NewProvider(
	audience string,
	roleARN string,
	jwtSource JWTSource,
	sessionDuration time.Duration,
	stsProvider STSProvider) (*Provider, error) {

	mySession := session.Must(session.NewSession())

	cfg := Provider{
		Expiry:          credentials.Expiry{},
		stsClient:       stsProvider(mySession),
		audience:        audience,
		RoleARN:         roleARN,
		RenewWindow:     time.Minute, // Default to 1 minute pre-renew. This avoids in-flight requests expiring.
		jwtSource:       jwtSource,
		SessionDuration: sessionDuration,
	}

	return &cfg, nil
}

type Provider struct {
	credentials.Expiry

	stsClient stsiface.STSAPI
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
		return credentials.Value{}, errors.Wrap(err, "failed to assume role")
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
		RoleArn:          &sp.RoleARN,
		RoleSessionName:  &sp.SessionName,
		WebIdentityToken: &token,
	}

	if len(sp.Policy) > 0 {
		assumeReq.Policy = &sp.Policy
	}

	if sp.SessionDuration != 0 {
		assumeReq.DurationSeconds = aws.Int64(int64(sp.SessionDuration.Seconds()))
	}

	if *assumeReq.RoleSessionName == "" {
		assumeReq.RoleSessionName = aws.String("spiffe-aws-assume-role")
	}

	for _, arn := range sp.PolicyARNs {
		assumeReq.PolicyArns = append(assumeReq.PolicyArns, &sts.PolicyDescriptorType{Arn: aws.String(arn)})
	}

	return sp.stsClient.AssumeRoleWithWebIdentityWithContext(ctx, &assumeReq)
}

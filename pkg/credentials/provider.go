package credentials

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/pkg/errors"
	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
)

func NewProvider(
	audience string,
	roleARN string,
	jwtSource JWTSource,
	sessionDuration time.Duration,
	stsClient stsiface.STSAPI,
	telemetry *telemetry.Telemetry) (*Provider, error) {

	cfg := Provider{
		Expiry:          credentials.Expiry{},
		stsClient:       stsClient,
		audience:        audience,
		RoleARN:         roleARN,
		RenewWindow:     time.Minute, // Default to 1 minute pre-renew. This avoids in-flight requests expiring.
		jwtSource:       jwtSource,
		SessionDuration: sessionDuration,
		telemetry:       telemetry,
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

	telemetry *telemetry.Telemetry
}

// SpiffeProvider implements the AWS credentials Provider interface
var _ credentials.Provider = &Provider{}

// Retrieve returns a set of credentials to use.
func (sp *Provider) Retrieve() (credentials.Value, error) {
	ctx := context.Background()

	token, err := sp.jwtSource.FetchToken(ctx)
	if err != nil {
		return credentials.Value{}, errors.Wrap(err, "failed to fetch JSON Web Token")
	}

	out, err := sp.assumeRole(ctx, token)
	if err != nil {
		return credentials.Value{}, errors.Wrap(err, fmt.Sprintf("failed to assume role %s", sp.RoleARN))
	}

	sp.Expiry.SetExpiration(*out.Credentials.Expiration, sp.RenewWindow)

	return credentials.Value{
		AccessKeyID:     *out.Credentials.AccessKeyId,
		SecretAccessKey: *out.Credentials.SecretAccessKey,
		SessionToken:    *out.Credentials.SessionToken,
		ProviderName:    "not sure what this is for!",
	}, nil
}

func (sp *Provider) assumeRole(ctx context.Context, token string) (output *sts.AssumeRoleWithWebIdentityOutput, err error) {
	emitMetrics := sp.telemetry.Instrument([]string{"Provider", "assumeRole"}, &err)
	defer emitMetrics()

	assumeReq := sp.newAssumeRoleRequest(token)

	for attempts := 0; attempts < 3; attempts++ {
		output, err = sp.stsClient.AssumeRoleWithWebIdentityWithContext(ctx, assumeReq)
		if hasErrorCode(err, sts.ErrCodeInvalidIdentityTokenException) {
			continue
		}

		break
	}

	return output, err
}

func (sp *Provider) newAssumeRoleRequest(token string) *sts.AssumeRoleWithWebIdentityInput {
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

	return &assumeReq
}

func hasErrorCode(err error, errorCode string) bool {
	if err == nil {
		return false
	}

	awsErr, ok := err.(awserr.Error)
	if !ok {
		return false
	}

	return awsErr.Code() == errorCode
}

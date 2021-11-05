package credentials

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/square/spiffe-aws-assume-role/internal/mocks"
	"github.com/square/spiffe-aws-assume-role/internal/test"
	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAssumeRoleFailsAfterThreeInvalidTokenExceptions(t *testing.T) {
	stsClient := mocks.STSAPI{}
	defer stsClient.AssertExpectations(t)

	invalidTokenException := awserr.New(sts.ErrCodeInvalidIdentityTokenException, "message", nil)
	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Return(nil, invalidTokenException).
		Times(3)

	provider := Provider{
		stsClient: &stsClient,
		telemetry: telemetry.MustNullTelemetry(),
		logger:    logrus.New(),
	}
	_, err := provider.assumeRole(context.Background(), "token")
	require.Error(t, err)
}

func TestAssumeRoleSucceedsAfterTwoInvalidTokenExceptions(t *testing.T) {
	stsClient := mocks.STSAPI{}
	defer stsClient.AssertExpectations(t)

	invalidTokenException := awserr.New(sts.ErrCodeInvalidIdentityTokenException, "message", nil)
	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Return(nil, invalidTokenException).
		Times(2)

	output := &sts.AssumeRoleWithWebIdentityOutput{}
	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Return(output, nil).
		Times(1)

	provider := Provider{
		stsClient: &stsClient,
		telemetry: telemetry.MustNullTelemetry(),
		logger:    logrus.New(),
	}
	_, err := provider.assumeRole(context.Background(), "token")
	require.NoError(t, err)
}

func TestDetectsInvalidIdentityTokenException(t *testing.T) {
	invalidTokenException := awserr.New(sts.ErrCodeInvalidIdentityTokenException, "message", nil)
	require.True(t, hasErrorCode(invalidTokenException, sts.ErrCodeInvalidIdentityTokenException))
}

func TestHasErrorCodeNilError(t *testing.T) {
	require.False(t, hasErrorCode(nil, sts.ErrCodeInvalidIdentityTokenException))
}

type MyError struct {
}

func (*MyError) Error() string {
	return "MyError"
}

func TestHasErrorCodeNonAwsError(t *testing.T) {
	nonAwsError := &MyError{}
	require.False(t, hasErrorCode(nonAwsError, sts.ErrCodeInvalidIdentityTokenException))
}

func TestHasErrorCodeWrongErrorCode(t *testing.T) {
	awsError := awserr.New("foo", "bar", nil)
	require.False(t, hasErrorCode(awsError, sts.ErrCodeInvalidIdentityTokenException))
}

func TestHasErrorCodeCorrectErrorCode(t *testing.T) {
	awsError := awserr.New(sts.ErrCodeInvalidIdentityTokenException, "message", nil)
	require.True(t, hasErrorCode(awsError, sts.ErrCodeInvalidIdentityTokenException))
}

func TestPassesSessionDurationToStsAssumeRole(t *testing.T) {
	stsClient := mocks.STSAPI{}
	defer stsClient.AssertExpectations(t)

	captor := test.Captor{}

	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Run(captor.Capture()).
		Return(&sts.AssumeRoleWithWebIdentityOutput{}, nil)

	nSeconds := randomInt32(1023) + 1
	sessionDuration := time.Duration(nSeconds) * time.Second

	provider := Provider{
		SessionDuration: sessionDuration,
		stsClient:       &stsClient,
		telemetry:       telemetry.MustNullTelemetry(),
		logger:          logrus.New(),
	}
	_, err := provider.assumeRole(context.Background(), "role")
	require.NoError(t, err)

	input := captor.Args.Get(1).(*sts.AssumeRoleWithWebIdentityInput)
	require.EqualValues(t, sessionDuration.Seconds(), *input.DurationSeconds)
}

func TestNewProviderAssignsSessionDuration(t *testing.T) {
	nonZeroSessionDuration := time.Duration(randomInt32(1023) + 1)
	sessionName := "testSession"

	var audience, roleArn string
	var jwtSource JWTSource

	provider, err := NewProvider(
		audience,
		roleArn,
		jwtSource,
		sessionName,
		nonZeroSessionDuration,
		nil,
		telemetry.MustNullTelemetry(),
		logrus.New())
	require.NoError(t, err)
	require.Equal(t, nonZeroSessionDuration, provider.SessionDuration)
}

func TestRetrieveSetsExpirationOnCredentials(t *testing.T) {
	var audience, roleArn string
	var sessionDuration = time.Second

	jwtSource := mocks.JWTSource{}
	defer jwtSource.AssertExpectations(t)
	jwtSource.
		On("FetchToken", mock.Anything).
		Return("token", nil)

	expiration := time.Now()
	copyOfExpiration := expiration

	credentials := sts.Credentials{
		AccessKeyId:     aws.String(""),
		Expiration:      &copyOfExpiration,
		SecretAccessKey: aws.String(""),
		SessionToken:    aws.String(""),
	}

	assumeRoleResponse := sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &credentials,
	}

	stsClient := mocks.STSAPI{}
	defer stsClient.AssertExpectations(t)
	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Return(&assumeRoleResponse, nil)

	sessionName := "testSession"

	provider, err := NewProvider(
		audience,
		roleArn,
		&jwtSource,
		sessionName,
		sessionDuration,
		&stsClient,
		telemetry.MustNullTelemetry(),
		logrus.New())
	require.NoError(t, err)

	_, err = provider.Retrieve()
	require.NoError(t, err)

	require.EqualValues(t,
		expiration.Round(0).Add(-time.Minute),
		provider.Expiry.ExpiresAt())
}

func TestAssumeRoleAppendsPolicies(t *testing.T) {
	stsClient := mocks.STSAPI{}
	defer stsClient.AssertExpectations(t)

	captor := test.Captor{}

	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Run(captor.Capture()).
		Return(&sts.AssumeRoleWithWebIdentityOutput{}, nil)

	policy := "foo"
	policyArn1 := "bar"
	policyArn2 := "baz"

	provider := Provider{
		Policy:     policy,
		PolicyARNs: []string{policyArn1, policyArn2},
		stsClient:  &stsClient,
		telemetry:  telemetry.MustNullTelemetry(),
		logger:     logrus.New(),
	}
	_, err := provider.assumeRole(context.Background(), "role")
	require.NoError(t, err)

	input := captor.Args.Get(1).(*sts.AssumeRoleWithWebIdentityInput)
	require.EqualValues(t, policy, *input.Policy)

	require.EqualValues(t, policyArn1, *input.PolicyArns[0].Arn)
	require.EqualValues(t, policyArn2, *input.PolicyArns[1].Arn)
}

func randomInt32(maxExclusive int32) int32 {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	return random.Int31n(maxExclusive)
}

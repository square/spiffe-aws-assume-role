package credentials

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/square/spiffe-aws-assume-role/internal/mocks"
	"github.com/square/spiffe-aws-assume-role/internal/test"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

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
	}
	_, err := provider.assumeRole(context.Background(), "role")
	require.NoError(t, err)

	input := captor.Args.Get(1).(*sts.AssumeRoleWithWebIdentityInput)
	require.EqualValues(t, sessionDuration.Seconds(), *input.DurationSeconds)
}

func TestNewProviderAssignsSessionDuration(t *testing.T) {
	nonZeroSessionDuration := time.Duration(randomInt32(1023) + 1)

	var audience, roleArn string
	var jwtSource JWTSource

	stsProvider := StaticSTSProvider(nil)

	provider, err := NewProvider(audience, roleArn, jwtSource, nonZeroSessionDuration, stsProvider)
	require.NoError(t, err)
	require.Equal(t, nonZeroSessionDuration, provider.SessionDuration)
}

func randomInt32(maxExclusive int32) int32 {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)
	return random.Int31n(maxExclusive)
}

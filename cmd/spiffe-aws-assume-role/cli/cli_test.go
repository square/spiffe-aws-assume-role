package cli

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/square/spiffe-aws-assume-role/internal/mocks"
	"github.com/square/spiffe-aws-assume-role/internal/test"
	"github.com/square/spiffe-aws-assume-role/pkg/credentials"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestParsesSessionDuration(t *testing.T) {
	args := []string{
		"credentials",
		"--session-duration=PT5M",
		// We only specify the following fields because they're required
		"--audience=foo",
		"--role-arn=bar",
		"--spiffe-id=baz",
	}
	context, err := parse(args)
	require.NoError(t, err)

	cli := context.Model.Target.Interface().(CLI)
	sessionDuration := cli.Credentials.SessionDuration
	require.EqualValues(t, 5, sessionDuration.Minutes())
}

func TestDisplaysTopLevelHelp(t *testing.T) {
	helpTest(t, []string{"--help"})
}

func TestDisplaysCredentialsHelp(t *testing.T) {
	helpTest(t, []string{"--help", "credentials"})
}

func helpTest(t *testing.T, args []string) {
	kong, err := newKong(&CLI{})
	require.NoError(t, err, "Failed to create a new Kong instance")

	exited := false
	kong.Exit = func(exitCode int) {
		require.EqualValues(t, 0, exitCode)
		exited = true
	}

	_, err = kong.Parse(args)
	require.Error(t, err, "Parsing should 'fail' since required arguments are not supplied when displaying help.")

	require.True(t, exited, "Kong did not attempt to exit. Normally it will invoke its Exit function after displaying help.")
}

func TestSetsCustomSessionDuration(t *testing.T) {
	args := []string{
		"credentials",
		"--audience=foo",
		"--role-arn=arn:aws:iam:123456789012:role/foo",
		"--session-duration=PT5M",
		"--spiffe-id=spiffe://foo",
		"--workload-socket=tcp://127.0.0.1:8080",
	}

	jwtSource := mocks.JWTSource{}
	defer jwtSource.AssertExpectations(t)
	jwtSource.
		On("FetchToken", mock.Anything).
		Return("token", nil)

	stsClient := mocks.STSAPI{}
	defer stsClient.AssertExpectations(t)

	stsCredentials := sts.Credentials{
		AccessKeyId:     aws.String(""),
		Expiration:      aws.Time(time.Now()),
		SecretAccessKey: aws.String(""),
		SessionToken:    aws.String(""),
	}

	output := sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &stsCredentials,
	}

	captor := test.Captor{}

	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Run(captor.Capture()).
		Return(&output, nil)

	context := CliContext{
		JWTSourceProvider: credentials.StaticJWTSourceProvider(&jwtSource),
		STSProvider:       credentials.StaticSTSProvider(&stsClient),
	}

	failOnError(t, Run(&context, args))

	input := captor.Args.Get(1).(*sts.AssumeRoleWithWebIdentityInput)
	require.EqualValues(t, 300, *input.DurationSeconds)
}

func failOnError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("%+v", err)
	}
}

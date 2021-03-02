package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/google/uuid"
	"github.com/square/spiffe-aws-assume-role/internal/mocks"
	"github.com/square/spiffe-aws-assume-role/internal/test"
	"github.com/square/spiffe-aws-assume-role/pkg/credentials"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var requiredArgs = []string{
	"credentials",
	"--audience=foo",
	"--role-arn=bar",
	"--spiffe-id=baz",
}

func TestErrorLogging(t *testing.T) {
	const logFileName = "spiffe-aws-assume-role.log"

	deleteFileIfExists(t, logFileName)
	defer deleteFileIfExists(t, logFileName)

	badSpiffeId := uuid.New().String()

	args := []string{
		"credentials",
		"--audience=foo",
		"--role-arn=bar",
		fmt.Sprintf("--spiffe-id=%s", badSpiffeId),
		fmt.Sprintf("--log-file-path=%s", logFileName),
	}
	err := RunWithDefaultContext(args)
	require.Error(t, err)

	bytes, err := ioutil.ReadFile(logFileName)
	require.NoError(t, err)
	logs := string(bytes)
	require.True(t, strings.Contains(logs, badSpiffeId))
}

func TestParsesSessionDuration(t *testing.T) {
	command := parseTest(t, "--session-duration=PT5M")
	require.EqualValues(t, 5, command.SessionDuration.Minutes())
}

func TestParsesStsEndpoint(t *testing.T) {
	stsEndpoint := uuid.New().String()
	command := parseTest(t, fmt.Sprintf("--sts-endpoint=%s", stsEndpoint))
	require.EqualValues(t, stsEndpoint, command.STSEndpoint)
}

func TestParsesLogFilePath(t *testing.T) {
	logFilePath := uuid.New().String()
	command := parseTest(t, fmt.Sprintf("--log-file-path=%s", logFilePath))
	require.EqualValues(t, logFilePath, command.LogFilePath)
}

func parseTest(t *testing.T, arg string) CredentialsCmd {
	args := append(requiredArgs, arg)

	context, err := parse(args)
	require.NoError(t, err)

	cli := context.Model.Target.Interface().(CLI)
	return cli.Credentials
}

func TestParsesStsRegion(t *testing.T) {
	stsRegion := uuid.New().String()

	args := []string{
		"credentials",
		fmt.Sprintf("--sts-region=%s", stsRegion),
		// We only specify the following fields because they're required
		"--audience=foo",
		"--role-arn=bar",
		"--spiffe-id=baz",
	}
	context, err := parse(args)
	require.NoError(t, err)

	cli := context.Model.Target.Interface().(CLI)
	require.EqualValues(t, stsRegion, cli.Credentials.STSRegion)
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

func TestSetsCustomStsEndpoint(t *testing.T) {
	stsEndpoint := uuid.New().String()

	args := []string{
		"credentials",
		"--audience=foo",
		"--role-arn=arn:aws:iam:123456789012:role/foo",
		fmt.Sprintf("--sts-endpoint=%s", stsEndpoint),
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

	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Return(&output, nil)

	var _session *session.Session
	stsProvider := func(s *session.Session) stsiface.STSAPI {
		_session = s
		return &stsClient
	}

	context := CliContext{
		JWTSourceProvider: credentials.StaticJWTSourceProvider(&jwtSource),
		STSProvider:       stsProvider,
	}

	failOnError(t, Run(&context, args))

	require.EqualValues(t, stsEndpoint, *_session.Config.Endpoint)
}

func TestSetsCustomStsRegion(t *testing.T) {
	stsRegion := uuid.New().String()

	args := []string{
		"credentials",
		"--audience=foo",
		"--role-arn=arn:aws:iam:123456789012:role/foo",
		fmt.Sprintf("--sts-region=%s", stsRegion),
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

	stsClient.
		On("AssumeRoleWithWebIdentityWithContext", mock.Anything, mock.Anything).
		Return(&output, nil)

	var _session *session.Session
	stsProvider := func(s *session.Session) stsiface.STSAPI {
		_session = s
		return &stsClient
	}

	context := CliContext{
		JWTSourceProvider: credentials.StaticJWTSourceProvider(&jwtSource),
		STSProvider:       stsProvider,
	}

	failOnError(t, Run(&context, args))

	require.EqualValues(t, stsRegion, *_session.Config.Region)
}

func TestCreatesSessionWithUnspecifiedEndpointAndRegion(t *testing.T) {
	require.NotNil(t, createSession("", ""))
}

func TestCreatesSessionWithCustomEndpointAndRegion(t *testing.T) {
	endpoint := uuid.New().String()
	s := createSession(endpoint, "")
	require.NotNil(t, s)
	require.EqualValues(t, endpoint, *s.Config.Endpoint)
}

func failOnError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("%+v", err)
	}
}

func deleteFileIfExists(t *testing.T, filename string) {
	_, err := os.Stat(filename)
	if err == nil {
		require.NoError(t, os.Remove(filename), fmt.Sprintf("failed to delete file %s", filename))
	}
}

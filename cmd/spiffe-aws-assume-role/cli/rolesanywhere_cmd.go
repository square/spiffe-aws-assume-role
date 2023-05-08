package cli

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	rolesanywhere "github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere/rolesanywhereiface"
	"github.com/evalphobia/logrus_sentry"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
)

type RolesAnywhereCmd struct {
	RoleARN                 string        `required:"" group:"AWS Config" help:"AWS Role ARN to assume"`
	JumpRoleARN             string        `optional:"" group:"AWS Config" help:"AWS Role in Trust Anchor account to assume role from"`
	TrustAnchorARN          string        `required:"" group:"AWS Config" help:"AWS TrustAnchor ARN to use for RolesAnywhere"`
	ProfileARN              string        `required:"" group:"AWS Config" help:"AWS Profile ARN to use for RolesAnywhere"`
	PrivateKey              string        `required:"" group:"AWS Config" help:"Private key for X.509 Certificate"`
	Certificate             string        `required:"" group:"AWS Config" help:"Certificate to be used with RolesAnywhere"`
	Endpoint                string        `optional:"" group:"AWS Config" help:"Endpoint to use for the RolesAnywhere Request"`
	SessionDuration         time.Duration `optional:"" group:"AWS Config" type:"iso8601duration" help:"AWS session duration in ISO8601 duration format (e.g. PT5M for five minutes)"`
	Region                  string        `optional:"" group:"AWS Config" help:"Trust Anchor region to use"`
	WithProxy               bool          `optional:""  group:"AWS Config" help:""`
	LogFilePath             string        `optional:"" group:"Process Config" help:"Path to log file"`
	TelemetrySocket         string        `optional:"" group:"Telemetry" help:"Socket address (TCP/UNIX) to emit metrics to (e.g. 127.0.0.1:8200)"`
	TelemetryName           string        `optional:"" group:"Telemetry" help:"Service Name for Telemetry Data"`
	TelemetryServiceAsLabel bool          `optional:"" group:"Telemetry" help:"Place the Service name as a label instead of prefix"`
	SentryDSN               string        `optional:"" group:"Process Config" help:"DSN from Sentry for sending errors (e.g.  https://<hash>@o123456.ingest.sentry.io/123456"`
	Debug                   bool          `optional:"" group:"Process Config" help:"Enable debug logging"`
}

type rolesAnywhereSignerData struct {
	privateKey    crypto.PrivateKey
	certificate   x509.Certificate
	intermediates []x509.Certificate
	data          aws_signing_helper.CertificateData
}

type rolesanywhereCreateCredsInput struct {
	createSessionRequest *rolesanywhere.CreateSessionInput
	rolesAnywhereClient  rolesanywhereiface.RolesAnywhereAPI
	signerData           *rolesAnywhereSignerData
}

type stsCreateCredsInput struct {
	stsClient       stsiface.STSAPI
	signerData      *rolesAnywhereSignerData
	sessionDuration int64
}

func (c *RolesAnywhereCmd) Run(context *CliContext) (err error) {
	c.configureLogger(context.Logger)
	c.configureSentry(context.Logger)

	t, err := c.configureTelemetry(context)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to configure telemetry for socket address %s", c.TelemetrySocket))
	}
	defer t.Close()
	context.Telemetry = t

	return c.RunRolesAnywhere(context, t)
}

// A significant change between RunRolesAnywhere and the aws_signing_helper.GenerateCredentials() is that
// RunRolesAnywhere will assume that the certificate and intermediates are bundled together. Much remains
// similar between the two functions.
func (c *RolesAnywhereCmd) RunRolesAnywhere(context *CliContext, telemetry *telemetry.Telemetry) (err error) {
	emitMetrics := telemetry.Instrument(context.TelemetryOpts.RolesAnywhereMetricName, &err)
	defer emitMetrics()

	var logLevel aws.LogLevelType
	if c.Debug {
		logLevel = aws.LogDebug
	} else {
		logLevel = aws.LogOff
	}

	// AWS calls use duration in in64 seconds
	durationSeconds := int64(c.SessionDuration.Seconds())

	// Determine if a jump role is required to be used, and which role to call with RolesAnywhere
	requireJump, rolesAnywhereArn, err := c.extractMultiAccountValues()
	if err != nil {
		return err
	}

	// Get certificate information and private key to use for RolesAnywhere
	signerData, err := c.extractCertificateData()
	if err != nil {
		return err
	}

	// Configure a client to use with RolesAnywhere
	rolesAnywhereClient, err := c.configureRolesAnywhereClient(signerData, logLevel)
	if err != nil {
		return err
	}

	// If we aren't using RolesAnywhere long-term, keep credential lifetime to a minimum
	// 15 minutes (900 seconds)
	rolesAnywhereDuration := int64((time.Minute * 15) / (time.Second))
	if !requireJump {
		rolesAnywhereDuration = durationSeconds
	}

	createRolesAnywhereCredsInput := rolesanywhereCreateCredsInput{
		createSessionRequest: &rolesanywhere.CreateSessionInput{
			Cert:               &signerData.data.CertificateData,
			ProfileArn:         &c.ProfileARN,
			TrustAnchorArn:     &c.TrustAnchorARN,
			DurationSeconds:    &rolesAnywhereDuration,
			InstanceProperties: nil,
			RoleArn:            &rolesAnywhereArn,
			SessionName:        nil,
		},
		rolesAnywhereClient: rolesAnywhereClient,
		signerData:          signerData,
	}

	// Get RolesAnywhere Creds
	output, err := c.createRolesAnywhereCreds(createRolesAnywhereCredsInput)

	// Use the RolesAnywhere Creds to jump to other account's role
	if requireJump {
		stsClient, err := c.createStsClient(output, logLevel)
		if err != nil {
			return err
		}

		createCredsInput := &stsCreateCredsInput{
			stsClient:       stsClient,
			signerData:      signerData,
			sessionDuration: durationSeconds,
		}
		output, err = c.createStsCredentials(createCredsInput)
		if err != nil {
			return err
		}
	}

	buf, err := json.Marshal(output)
	if err != nil {
		return errors.Wrap(err, "failed to marshal temporary credentials")
	}

	// Print the string formatted credentialProcessOutput for consumption by credentials-process
	_, err = fmt.Print(string(buf[:]))

	return err
}

// Extract the requirement for usage of a Jump Role and which Role to use for the RolesAnywhere call
func (c *RolesAnywhereCmd) extractMultiAccountValues() (requireJump bool, rolesAnywhereArn string, err error) {
	// Parse the Trust Anchor Arn -- will inform some later decisions
	trustAnchorArn, err := arn.Parse(c.TrustAnchorARN)
	if err != nil {
		return false, "", err
	}

	// If a region is not explicitly specified, retrieve it from the Trust Anchor ARN
	if c.Region == "" {
		c.Region = trustAnchorArn.Region
	}

	// Parse the intended role-to-assume
	targetRoleArn, err := arn.Parse(c.RoleARN)
	if err != nil {
		return false, "", err
	}

	// Optimistically assume that the target role is in the trust anchor account
	rolesAnywhereArn = c.RoleARN
	requireJump = false

	// If the target role is not in the trust anchor account, a jump role is required
	if targetRoleArn.AccountID != trustAnchorArn.AccountID {
		requireJump = true

		if c.JumpRoleARN == "" {
			return false, "", fmt.Errorf("cross-account access is currently not supported by the RolesAnywhere service")
		}

		jumpRoleArn, err := arn.Parse(c.JumpRoleARN)
		if err != nil {
			return false, "", fmt.Errorf("malformed jump role arn")
		}

		if jumpRoleArn.AccountID != trustAnchorArn.AccountID {
			return false, "", fmt.Errorf("jump role is not in the same account as trust anchor")
		}

		rolesAnywhereArn = c.JumpRoleARN
	}

	return requireJump, rolesAnywhereArn, nil
}

// Extract certificate data from the files provided as arguments to the command
func (c *RolesAnywhereCmd) extractCertificateData() (*rolesAnywhereSignerData, error) {

	// Read Private Key file and make into a crypto.PrivateKey
	privateKey, err := aws_signing_helper.ReadPrivateKeyData(c.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Read the certificate bundle (inclusive of leaf certificate)
	var certificateChain []x509.Certificate
	{
		certificateChainPointers, err := aws_signing_helper.ReadCertificateBundleData(c.Certificate)
		if err != nil {
			return nil, err
		}
		for _, certificate := range certificateChainPointers {
			certificateChain = append(certificateChain, *certificate)
		}
	}

	// Collect certificate and any intermediates
	certificate := certificateChain[0]
	var intermediates []x509.Certificate
	if len(certificateChain) > 1 {
		intermediates = certificateChain[1:]
	}

	//extract key type
	var keyType string
	switch certificate.PublicKeyAlgorithm {
	case x509.RSA:
		keyType = "RSA"
	case x509.ECDSA:
		keyType = "EC"
	default:
		keyType = ""
	}

	// List supported algorithms
	supportedAlgorithms := []string{
		fmt.Sprintf("%sSHA256", keyType),
		fmt.Sprintf("%sSHA384", keyType),
		fmt.Sprintf("%sSHA512", keyType),
	}

	// Populate the certificate data for the signing a session request
	certificateData := aws_signing_helper.CertificateData{
		KeyType:         keyType,
		CertificateData: base64.StdEncoding.EncodeToString(certificate.Raw),
		SerialNumber:    certificate.SerialNumber.String(),
		Algorithms:      supportedAlgorithms,
	}

	// Return the private key and certificate data for use in RolesAnywhere
	return &rolesAnywhereSignerData{privateKey, certificate, intermediates, certificateData}, nil
}

// Configure a client to use RolesAnywhere and its Sigv4 signing scheme
func (c *RolesAnywhereCmd) configureRolesAnywhereClient(signData *rolesAnywhereSignerData, logLevel aws.LogLevelType) (*rolesanywhere.RolesAnywhere, error) {
	// Start a new session
	mySession := session.Must(session.NewSession())

	var tr *http.Transport
	if c.WithProxy {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			Proxy:           http.ProxyFromEnvironment,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}

	// Create a new HTTP client with handlers for signing
	client := &http.Client{Transport: tr}
	config := aws.NewConfig().WithRegion(c.Region).WithHTTPClient(client).WithLogLevel(logLevel)
	if c.Endpoint != "" {
		config.WithEndpoint(c.Endpoint)
	}
	rolesAnywhereClient := rolesanywhere.New(mySession, config)
	rolesAnywhereClient.Handlers.Build.RemoveByName("core.SDKVersionUserAgentHandler")
	rolesAnywhereClient.Handlers.Build.PushBackNamed(request.NamedHandler{Name: "v4x509.SpiffeAwsAssumeRoleUserAgentHandler", Fn: request.MakeAddToUserAgentHandler("SpiffeAwsAssumeRole", "1", runtime.Version(), runtime.GOOS, runtime.GOARCH)})
	rolesAnywhereClient.Handlers.Sign.Clear()
	rolesAnywhereClient.Handlers.Sign.PushBackNamed(request.NamedHandler{Name: "v4x509.SignRequestHandler", Fn: aws_signing_helper.CreateSignFunction(signData.privateKey, signData.certificate, signData.intermediates)})

	return rolesAnywhereClient, nil
}

// Use a RolesAnywhere client to collect Role credentials
func (c *RolesAnywhereCmd) createRolesAnywhereCreds(input rolesanywhereCreateCredsInput) (*aws_signing_helper.CredentialProcessOutput, error) {
	// Create the session
	output, err := input.rolesAnywhereClient.CreateSession(input.createSessionRequest)
	if err != nil {
		return nil, err
	}

	// Make sure we got temp creds from AWS
	if len(output.CredentialSet) == 0 {
		return nil, fmt.Errorf("unable to obtain temporary security credentials from CreateSession")
	}
	rolesAnywhereCredentials := output.CredentialSet[0].Credentials
	return &aws_signing_helper.CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     *rolesAnywhereCredentials.AccessKeyId,
		SecretAccessKey: *rolesAnywhereCredentials.SecretAccessKey,
		SessionToken:    *rolesAnywhereCredentials.SessionToken,
		Expiration:      *rolesAnywhereCredentials.Expiration,
	}, nil
}

// Create a new STS Client to use with the Jump Role
func (c *RolesAnywhereCmd) createStsClient(jumpCreds *aws_signing_helper.CredentialProcessOutput, logLevel aws.LogLevelType) (stsiface.STSAPI, error) {
	credsForSts := aws.NewConfig().WithCredentials(
		credentials.NewStaticCredentials(
			jumpCreds.AccessKeyId, jumpCreds.SecretAccessKey, jumpCreds.SessionToken,
		),
	).WithRegion("us-west-2").WithLogLevel(logLevel)

	stsSession := session.Must(session.NewSession(credsForSts))

	return sts.New(stsSession), nil
}

// Assume the Target Role from the Jump Role, setting the session name to the SPIFFE URI if possible
// or to the Common Name if not
func (c *RolesAnywhereCmd) createStsCredentials(input *stsCreateCredsInput) (*aws_signing_helper.CredentialProcessOutput, error) {
	var sessionName string
	// If we can use a URI to form a session name, do that
	if input.signerData.certificate.URIs != nil && len(input.signerData.certificate.URIs) > 0 {
		sessionName = strings.ReplaceAll((input.signerData.certificate.URIs[0].Hostname() + input.signerData.certificate.URIs[0].EscapedPath()), "/", ".")
	} else {
		sessionName = input.signerData.certificate.Subject.CommonName
	}

	arInput := &sts.AssumeRoleInput{
		DurationSeconds: &input.sessionDuration,
		RoleArn:         &c.RoleARN,
		RoleSessionName: &sessionName,
	}

	// Assume our target role
	arOutput, err := input.stsClient.AssumeRole(arInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate temporary credentials")
	}

	// Return creds in Credential Process Output format
	return &aws_signing_helper.CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     *arOutput.Credentials.AccessKeyId,
		SecretAccessKey: *arOutput.Credentials.SecretAccessKey,
		SessionToken:    *arOutput.Credentials.SessionToken,
		Expiration:      arOutput.Credentials.Expiration.Format(time.RFC3339),
	}, nil
}

func (c *RolesAnywhereCmd) configureLogger(logger *logrus.Logger) {
	if len(c.LogFilePath) > 0 {
		file, err := os.OpenFile(c.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.Info(errors.Wrapf(err, "Failed to log to file %s, using default of stderr", c.LogFilePath))
		} else {
			logger.Out = io.MultiWriter(os.Stderr, file)
		}
	}
	if c.Debug {
		logger.Level = logrus.DebugLevel
	}
}

func (c *RolesAnywhereCmd) configureTelemetry(context *CliContext) (t *telemetry.Telemetry, err error) {
	if c.TelemetrySocket != "" {
		context.TelemetryOpts.Socket = c.TelemetrySocket
	}

	if c.TelemetryName != "" {
		context.TelemetryOpts.ServiceName = c.TelemetryName
	}

	if c.TelemetryServiceAsLabel {
		context.TelemetryOpts.ServiceAsLabel = c.TelemetryServiceAsLabel
	}

	t, err = telemetry.NewTelemetry(context.TelemetryOpts)
	if err != nil {
		return nil, err
	}

	for label, value := range context.TelemetryOpts.Labels {
		t.AddLabel(label, value)
	}

	return t, err
}

func (c *RolesAnywhereCmd) configureSentry(logger *logrus.Logger) {
	if c.SentryDSN == "" {
		return
	}

	hook, err := logrus_sentry.NewSentryHook(c.SentryDSN, []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
	})

	if err != nil {
		logger.Fatalf("unable to initialize Sentry Hook %v", err)
	}

	logger.Hooks.Add(hook)
}

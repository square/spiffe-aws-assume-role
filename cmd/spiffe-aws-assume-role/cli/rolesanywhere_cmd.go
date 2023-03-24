package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	rolesanywhere "github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
	"github.com/evalphobia/logrus_sentry"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
)

type RolesAnywhereCmd struct {
	RoleARN         string        `required:"" group:"AWS Config" help:"AWS Role ARN to assume"`
	TrustAnchorARN  string        `required:"" group:"AWS Config" help:"AWS TrustAnchor ARN to use for RolesAnywhere"`
	ProfileARN      string        `required:"" group:"AWS Config" help:"AWS Profile ARN to use for RolesAnywhere"`
	PrivateKey      string        `required:"" group:"AWS Config" help:"Private key for X.509 Certificate"`
	Certificate     string        `required:"" group:"AWS Config" help:"Certificate to be used with RolesAnywhere"`
	Endpoint        string        `optional:"" group:"AWS Config" help:"Endpoint to use for the RolesAnywhere Request"`
	SessionDuration time.Duration `optional:"" group:"AWS Config" type:"iso8601duration" help:"AWS session duration in ISO8601 duration format (e.g. PT5M for five minutes)"`
	Region          string        `optional:"" group:"AWS Config" help:"Trust Anchor region to use"`
	WithProxy       bool          `optional:""  group:"AWS Config" help:""`
	LogFilePath     string        `optional:"" group:"Process Config" help:"Path to log file"`
	TelemetrySocket string        `optional:"" group:"Process Config" help:"Socket address (TCP/UNIX) to emit metrics to (e.g. 127.0.0.1:8200)"`
	SentryDSN       string        `optional:"" group:"Process Config" help:"DSN from Sentry for sending errors (e.g.  https://<hash>@o123456.ingest.sentry.io/123456"`
	Debug           bool          `optional:"" group:"Process Config" help:"Enable debug logging"`
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
	emitMetrics := telemetry.Instrument([]string{"cli", "rolesanywhere"}, &err)
	defer emitMetrics()

	// If a region is not explicitly specified, retrieve it from the Trust Anchor ARN
	if c.Region == "" {
		taArn, err := arn.Parse(c.TrustAnchorARN)
		if err != nil {
			return err
		}

		c.Region = taArn.Region
	}

	// Read Private Key file and make into a crypto.PrivateKey
	privateKey, err := helper.ReadPrivateKeyData(c.PrivateKey)

	// Read the certificate bundle (inclusive of leaf certificate)
	var certificateChain []x509.Certificate
	{
		certificateChainPointers, err := helper.ReadCertificateBundleData(c.Certificate)
		if err != nil {
			return err
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

	supportedAlgorithms := []string{
		fmt.Sprintf("%sSHA256", keyType),
		fmt.Sprintf("%sSHA384", keyType),
		fmt.Sprintf("%sSHA512", keyType),
	}

	// Populate the certificate data for the signing a session request
	certificateData := helper.CertificateData{
		KeyType:         keyType,
		CertificateData: base64.StdEncoding.EncodeToString(certificate.Raw),
		SerialNumber:    certificate.SerialNumber.String(),
		Algorithms:      supportedAlgorithms,
	}

	mySession := session.Must(session.NewSession())

	var logLevel aws.LogLevelType
	if c.Debug {
		logLevel = aws.LogDebug
	} else {
		logLevel = aws.LogOff
	}

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
	rolesAnywhereClient.Handlers.Sign.PushBackNamed(request.NamedHandler{Name: "v4x509.SignRequestHandler", Fn: helper.CreateSignFunction(privateKey, certificate, intermediates)})

	// Create the Session Request Object
	durationSeconds := int64(c.SessionDuration.Seconds())
	createSessionRequest := rolesanywhere.CreateSessionInput{
		Cert:               &certificateData.CertificateData,
		ProfileArn:         &c.ProfileARN,
		TrustAnchorArn:     &c.TrustAnchorARN,
		DurationSeconds:    &(durationSeconds),
		InstanceProperties: nil,
		RoleArn:            &c.RoleARN,
		SessionName:        nil,
	}

	// Create the session
	output, err := rolesAnywhereClient.CreateSession(&createSessionRequest)
	if err != nil {
		return err
	}

	if len(output.CredentialSet) == 0 {
		msg := "unable to obtain temporary security credentials from CreateSession"
		return errors.New(msg)
	}

	// Parse the temporary credentials
	credentials := output.CredentialSet[0].Credentials
	credentialProcessOutput := helper.CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     *credentials.AccessKeyId,
		SecretAccessKey: *credentials.SecretAccessKey,
		SessionToken:    *credentials.SessionToken,
		Expiration:      *credentials.Expiration,
	}

	// RolesAnywhereHelper will use the CreateSession API and sign the request
	// and returns credentialProcessOutput as a json
	if err != nil {
		return errors.Wrap(err, "failed to generate temporary credentials")
	}

	buf, err := json.Marshal(credentialProcessOutput)
	if err != nil {
		return errors.Wrap(err, "failed to marshal temporary credentials")
	}

	// Print the string formatted credentialProcessOutput for consumption by credentials-process
	_, err = fmt.Print(string(buf[:]))

	return err
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

	t, err = telemetry.NewTelemetry(context.TelemetryOpts)

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

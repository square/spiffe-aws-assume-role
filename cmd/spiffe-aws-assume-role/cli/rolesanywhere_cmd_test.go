package cli

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere/rolesanywhereiface"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

type mockedRolesanywhereCreateSession struct {
	rolesanywhereiface.RolesAnywhereAPI
	Output rolesanywhere.CreateSessionOutput
}

func (m mockedRolesanywhereCreateSession) CreateSession(in *rolesanywhere.CreateSessionInput) (*rolesanywhere.CreateSessionOutput, error) {
	return &m.Output, nil
}

type mockedStsAssumeRole struct {
	stsiface.STSAPI
	Output sts.AssumeRoleOutput
}

func (m mockedStsAssumeRole) AssumeRole(in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return &m.Output, nil
}

func TestConfigureRolesAnywhere(t *testing.T) {
	assert := assert.New(t)

	signerData, err := createTestCertificateData()
	assert.NoError(err)

	c := &RolesAnywhereCmd{WithProxy: false}

	client, err := c.configureRolesAnywhereClient(signerData, aws.LogOff)
	assert.NoError(err)
	assert.NotNil(client)
}

func TestCreateCreds(t *testing.T) {
	assert := assert.New(t)

	expiration := time.Now().Format(time.RFC3339)

	expected := aws_signing_helper.CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AZBIFITESTESTEST",
		SecretAccessKey: "TeSt/64abc",
		SessionToken:    "SessionTokenTest",
		Expiration:      expiration,
	}

	mockRAClient := mockedRolesanywhereCreateSession{
		Output: rolesanywhere.CreateSessionOutput{
			CredentialSet: []*rolesanywhere.CredentialResponse{
				{
					Credentials: &rolesanywhere.Credentials{
						AccessKeyId:     &expected.AccessKeyId,
						SecretAccessKey: &expected.SecretAccessKey,
						SessionToken:    &expected.SessionToken,
						Expiration:      &expiration,
					},
				},
			},
		},
	}

	// Data only consumed by API
	c := RolesAnywhereCmd{}
	rolesAnywhereDuration := int64(900)
	rolesAnywhereArn := ""

	signerData, err := createTestCertificateData()
	assert.NoError(err)

	createSessionInput := &rolesanywhere.CreateSessionInput{
		Cert:               &signerData.data.CertificateData,
		ProfileArn:         &c.ProfileARN,
		TrustAnchorArn:     &c.TrustAnchorARN,
		DurationSeconds:    &rolesAnywhereDuration,
		InstanceProperties: nil,
		RoleArn:            &rolesAnywhereArn,
		SessionName:        nil,
	}

	createRolesAnywhereCredsInput := rolesanywhereCreateCredsInput{
		createSessionRequest: createSessionInput,
		rolesAnywhereClient:  mockRAClient,
		signerData:           signerData,
	}

	output, err := c.createRolesAnywhereCreds(createRolesAnywhereCredsInput)
	assert.NoError(err)

	assert.Equal(output, &expected)
}

func TestFailedCreateCreds(t *testing.T) {
	assert := assert.New(t)

	mockRAClient := mockedRolesanywhereCreateSession{
		Output: rolesanywhere.CreateSessionOutput{
			CredentialSet: []*rolesanywhere.CredentialResponse{},
		},
	}

	// Data only consumed by API
	c := RolesAnywhereCmd{}
	rolesAnywhereDuration := int64(900)
	rolesAnywhereArn := ""

	signerData, err := createTestCertificateData()
	assert.NoError(err)

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
		rolesAnywhereClient: mockRAClient,
		signerData:          signerData,
	}

	output, err := c.createRolesAnywhereCreds(createRolesAnywhereCredsInput)
	assert.Error(err)
	assert.Nil(output)
}

func TestCreateStsCredentials(t *testing.T) {
	assert := assert.New(t)
	currentTime := time.Now()

	signerData, err := createTestCertificateData()
	assert.NoError(err)

	expected := aws_signing_helper.CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AZBIFITESTESTEST",
		SecretAccessKey: "TeSt/64abc",
		SessionToken:    "SessionTokenTest",
		Expiration:      currentTime.Format(time.RFC3339),
	}

	c := RolesAnywhereCmd{}

	mockSts := mockedStsAssumeRole{
		Output: sts.AssumeRoleOutput{
			Credentials: &sts.Credentials{
				AccessKeyId:     &expected.AccessKeyId,
				SecretAccessKey: &expected.SecretAccessKey,
				SessionToken:    &expected.SessionToken,
				Expiration:      &currentTime,
			},
		},
	}

	input := stsCreateCredsInput{
		stsClient:       mockSts,
		signerData:      signerData,
		sessionDuration: int64(900),
	}

	output, err := c.createStsCredentials(&input)
	assert.Equal(&expected, output)
	assert.NoError(err)
}

func TestExtractMultiAccountValuesValuesJumpRequired(t *testing.T) {
	assert := assert.New(t)

	c := RolesAnywhereCmd{
		TrustAnchorARN: fmt.Sprintf("arn:aws:rolesanywhere:us-east-1:012345678901:trust-anchor/%s", uuid.New().String()),
		RoleARN:        "arn:aws:iam::123456789012:role/test",
		JumpRoleARN:    "arn:aws:iam::012345678901:role/jump",
	}

	requireJump, firstRoleArn, err := c.extractMultiAccountValues()
	assert.NoError(err)
	assert.True(requireJump)
	assert.Equal(firstRoleArn, c.JumpRoleARN)
}

func TestExtractMultiAccountValuesNoJumpRequired(t *testing.T) {
	assert := assert.New(t)

	c := RolesAnywhereCmd{
		TrustAnchorARN: fmt.Sprintf("arn:aws:rolesanywhere:us-east-1:012345678901:trust-anchor/%s", uuid.New().String()),
		RoleARN:        "arn:aws:iam::012345678901:role/test",
	}

	requireJump, firstRoleArn, err := c.extractMultiAccountValues()
	assert.NoError(err)
	assert.False(requireJump)
	assert.Equal(firstRoleArn, c.RoleARN)
}

func TestExtractMultiAccountValuesJumpRequiredNoJumpRole(t *testing.T) {
	assert := assert.New(t)

	c := RolesAnywhereCmd{
		TrustAnchorARN: fmt.Sprintf("arn:aws:rolesanywhere:us-east-1:012345678901:trust-anchor/%s", uuid.New().String()),
		RoleARN:        "arn:aws:iam::123456789012:role/test",
	}

	_, _, err := c.extractMultiAccountValues()
	assert.Error(err)
}

func TestExtractMultiAccountValuesJumpRequiredBadJumpRole(t *testing.T) {
	assert := assert.New(t)

	c := RolesAnywhereCmd{
		TrustAnchorARN: fmt.Sprintf("arn:aws:rolesanywhere:us-east-1:012345678901:trust-anchor/%s", uuid.New().String()),
		RoleARN:        "arn:aws:iam::123456789012:role/test",
		JumpRoleARN:    "arn:aws:iam::234567890123:role/jump",
	}

	_, _, err := c.extractMultiAccountValues()
	assert.Error(err)
}

func createTestCertificateData() (*rolesAnywhereSignerData, error) {
	testKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	workloadKey, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return nil, err
	}

	testUrl, err := url.Parse("spiffe://test")
	if err != nil {
		return nil, err
	}

	workloadUrl, err := url.Parse("spiffe://test/workload")
	if err != nil {
		return nil, err
	}

	intermediateTemplate := []x509.Certificate{{URIs: []*url.URL{testUrl}, Subject: pkix.Name{CommonName: "test"}, IsCA: true, SerialNumber: big.NewInt(0)}}
	workloadTemplate := x509.Certificate{URIs: []*url.URL{workloadUrl}, Subject: pkix.Name{CommonName: "workload"}, SerialNumber: big.NewInt(1)}

	test, err := x509.CreateCertificate(rand.Reader, &intermediateTemplate[0], &intermediateTemplate[0], testKey.Public(), testKey)
	if err != nil {
		return nil, err
	}

	workload, err := x509.CreateCertificate(rand.Reader, &workloadTemplate, &intermediateTemplate[0], workloadKey.Public(), workloadKey)
	if err != nil {
		return nil, err
	}

	workloadCert, err := x509.ParseCertificate(workload)
	if err != nil {
		return nil, err
	}

	intermediateCert, err := x509.ParseCertificate(test)
	if err != nil {
		return nil, err
	}

	intermediates := []x509.Certificate{*intermediateCert}

	data := aws_signing_helper.CertificateData{
		KeyType:         "RSA",
		CertificateData: base64.StdEncoding.EncodeToString(workloadCert.Raw),
		SerialNumber:    workloadCert.SerialNumber.String(),
		Algorithms: []string{
			fmt.Sprintf("%sSHA256", "RSA"),
			fmt.Sprintf("%sSHA384", "RSA"),
			fmt.Sprintf("%sSHA512", "RSA"),
		},
	}

	return &rolesAnywhereSignerData{workloadKey, *workloadCert, intermediates, data}, nil
}

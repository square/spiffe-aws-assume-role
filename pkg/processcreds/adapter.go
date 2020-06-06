// processcreds takes a standard AWS credentials provider and provides a method
// to serialize credentials per the AWS processcreds specification.
package processcreds

import (
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

// ExpiringProvider is required so we know when the credentials expire
type ExpiringProvider interface {
	credentials.Provider
	credentials.Expirer
}

// CredentialOutput is the JSON format expected by the AWS processcreds provider
type CredentialOutput struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      *time.Time
}

// SerializeCredentials takes an ExpiringProvider and returns a serialized JSON document.
// It is suitable for printing to standard out in an aws credentials_process.
func SerializeCredentials(ep ExpiringProvider) ([]byte, error) {
	creds, err := ep.Retrieve()
	if err != nil {
		return nil, err
	}

	// It's important we call ExpiresAt after Retrieve, so we get the value for the current credentials
	exp := ep.ExpiresAt()

	return json.Marshal(CredentialOutput{
		Version:         1,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      &exp,
	})
}

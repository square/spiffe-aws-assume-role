package credentials

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/square/spiffe-aws-assume-role/internal/mocks"
	"github.com/stretchr/testify/require"
)

func TestStandardSTSProviderWithEmptySession(t *testing.T) {
	session, err := session.NewSession()
	require.NoError(t, err)
	sts := StandardSTSProvider(session)
	require.NotNil(t, sts)
}

func TestStaticSTSProviderReturnsProvidedInstance(t *testing.T) {
	sts := mocks.STSAPI{}
	provided := StaticSTSProvider(&sts)(nil)
	require.Same(t, &sts, provided)
}

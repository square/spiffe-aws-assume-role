package credentials

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	workloadConnTimeout = 3 * time.Second
)

type JWTSVIDSource struct {
	JWTSource

	subject        spiffeid.ID
	audience       string
	workloadSocket string
}

func NewJWTSVIDSource(subject spiffeid.ID, workloadSocket string, audience string) *JWTSVIDSource {
	return &JWTSVIDSource{
		subject:        subject,
		audience:       audience,
		workloadSocket: workloadSocket,
	}
}

func (jss *JWTSVIDSource) FetchToken(ctx context.Context) (string, error) {
	var dialOpts []workloadapi.JWTSourceOption

	if jss.workloadSocket != "" {
		dialOpts = append(dialOpts, workloadapi.WithClientOptions(workloadapi.WithAddr(jss.workloadSocket), workloadapi.WithDialOptions(grpc.WithNoProxy())))
	}

	ctx, cancel := context.WithTimeout(ctx, workloadConnTimeout)
	defer cancel()

	jwtSource, err := workloadapi.NewJWTSource(ctx, dialOpts...)
	if err != nil {
		return "", errors.Wrap(err, "creating JWT-SVID source")
	}

	jwt, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: jss.audience,
		Subject:  jss.subject,
	})
	if err != nil {
		return "", errors.Wrap(err, "retrieving JWT-SVID")
	}

	return jwt.Marshal(), nil
}

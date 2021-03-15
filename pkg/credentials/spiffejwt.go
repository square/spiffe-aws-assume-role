package credentials

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/square/spiffe-aws-assume-role/pkg/telemetry"
	"google.golang.org/grpc"
)

const (
	workloadConnTimeout = 3 * time.Second
)

type JWTSVIDSource struct {
	JWTSource

	subject        spiffeid.ID
	audience       string
	workloadSocket string
	logger         logger.Logger
	telemetry      *telemetry.Telemetry
}

func NewJWTSVIDSource(
	subject spiffeid.ID,
	workloadSocket string,
	audience string,
	logger logger.Logger,
	telemetry *telemetry.Telemetry) *JWTSVIDSource {

	return &JWTSVIDSource{
		subject:        subject,
		audience:       audience,
		workloadSocket: workloadSocket,
		logger:         logger,
		telemetry:      telemetry,
	}
}

func (jss *JWTSVIDSource) FetchToken(ctx context.Context) (token string, err error) {
	emitMetrics := jss.telemetry.Instrument([]string{"JWTSVIDSource", "FetchToken"}, &err)
	defer emitMetrics()

	var dialOpts []workloadapi.JWTSourceOption

	if jss.workloadSocket != "" {
		dialOpts = append(dialOpts, workloadapi.WithClientOptions(
			workloadapi.WithAddr(jss.workloadSocket),
			workloadapi.WithDialOptions(grpc.WithNoProxy()),
			workloadapi.WithLogger(jss.logger)))
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

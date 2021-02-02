package credentials

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type JWTSourceProvider func(subject spiffeid.ID, workloadSocket string, audience string) JWTSource

func StandardJWTSourceProvider(subject spiffeid.ID, workloadSocket string, audience string) JWTSource {
	return NewJWTSVIDSource(subject, workloadSocket, audience)
}

func StaticJWTSourceProvider(source JWTSource) func(spiffeid.ID, string, string) JWTSource {
	return func(spiffeid.ID, string, string) JWTSource {
		return source
	}
}

package credentials

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

type STSProvider func(*session.Session) stsiface.STSAPI

func StandardSTSProvider(session *session.Session) stsiface.STSAPI {
	return sts.New(session)
}

func StaticSTSProvider(sts stsiface.STSAPI) func(*session.Session) stsiface.STSAPI {
	return func(*session.Session) stsiface.STSAPI {
		return sts
	}
}

package test

import (
	"github.com/stretchr/testify/mock"
)

type Captor struct {
	Args mock.Arguments
}

func (c *Captor) Capture() func(mock.Arguments) {
	return func(args mock.Arguments) {
		c.Args = args
	}
}

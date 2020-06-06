package main

import (
	"fmt"
	"os"

	"github.com/square/spiffe-aws-assume-role/cmd/spiffe-aws-assume-role/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

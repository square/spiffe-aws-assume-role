package util

import (
	"reflect"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestStandardLibraryCannotParseIso8601Duration(t *testing.T) {
	_, err := time.ParseDuration("PT5M")
	require.Error(t, err, "Standard library was able to parse ISO8601 duration string, iso8601DurationMapper may no longer be needed")
}

func TestDecodesIso8601Duration(t *testing.T) {
	scanner := kong.Scan("PT5M")

	context := kong.DecodeContext{
		Scan: scanner,
	}
	var duration time.Duration
	target := reflect.ValueOf(&duration).Elem()

	err := Iso8601DurationMapper{}.Decode(&context, target)
	require.NoError(t, err)

	require.EqualValues(t, 5, duration.Minutes())
}

func TestDecodesIso8601DurationFromCli(t *testing.T) {
	type CLI struct {
		Duration time.Duration `type:"iso8601duration"`
	}

	parser, err := kong.New(&CLI{}, kong.NamedMapper(Iso8601DurationMapperType, Iso8601DurationMapper{}))
	require.NoError(t, err)

	args := []string{"--duration=PT99S"}
	context, err := parser.Parse(args)
	require.NoError(t, err)

	cli := context.Model.Target.Interface().(CLI)
	duration := cli.Duration
	require.EqualValues(t, 99, duration.Seconds())
}

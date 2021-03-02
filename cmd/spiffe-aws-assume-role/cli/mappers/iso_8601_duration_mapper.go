package mappers

import (
	"fmt"
	"reflect"

	"github.com/alecthomas/kong"
	iso8601duration "github.com/channelmeter/iso8601duration"
	"github.com/pkg/errors"
)

const Iso8601DurationMapperType = "iso8601duration"

type Iso8601DurationMapper struct {
	kong.Mapper
}

func (Iso8601DurationMapper) Decode(context *kong.DecodeContext, target reflect.Value) error {
	token, err := context.Scan.PopValue(Iso8601DurationMapperType)
	if err != nil {
		return errors.Wrap(err, "Failed to parse ISO 8601 duration from command line")
	}

	rawValue := token.Value.(string)
	isoDuration, err := iso8601duration.FromString(rawValue)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Failed to parse %s into an ISO 8601 duration", rawValue))
	}
	duration := isoDuration.ToDuration()
	target.Set(reflect.ValueOf(duration))

	return nil
}

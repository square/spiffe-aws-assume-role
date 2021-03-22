package telemetry

import (
	"reflect"
	"unsafe"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/armon/go-metrics/datadog"
)

type CloseableDogStatsdSink struct {
	*datadog.DogStatsdSink
}

var _ CloseableMetricSink = (*CloseableDogStatsdSink)(nil)

func NewCloseableDogStatsdSink(addr string, hostName string) (*CloseableDogStatsdSink, error) {
	dogStatsdSink, err := datadog.NewDogStatsdSink(addr, hostName)
	if err != nil {
		return nil, err
	}

	sink := &CloseableDogStatsdSink{
		DogStatsdSink: dogStatsdSink,
	}
	return sink, nil
}

func (s *CloseableDogStatsdSink) Close() {
	structValue := reflect.ValueOf(s.DogStatsdSink).Elem()
	privateField := structValue.FieldByName("client")
	fieldValue := reflect.NewAt(privateField.Type(), unsafe.Pointer(privateField.UnsafeAddr())).Elem()
	statsdClient := fieldValue.Interface().(*statsd.Client)
	_ = statsdClient.Close()
}

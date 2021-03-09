package telemetry

import (
	"time"

	metrics "github.com/armon/go-metrics"
	"github.com/armon/go-metrics/datadog"
)

const (
	noAddress   = ""
	noHostName  = ""
	serviceName = "spiffe-aws-assume-role"

	calls   = "Calls"
	failure = "Failure"
	latency = "Latency"
	success = "Success"
)

type Telemetry struct {
	Metrics *metrics.Metrics
}

func NullTelemetry() (*Telemetry, error) {
	return NewTelemetryForSink(&metrics.BlackholeSink{})
}

func MustNullTelemetry() *Telemetry {
	telemetry, err := NullTelemetry()
	if err != nil {
		panic(err)
	}
	return telemetry
}

func NewTelemetry(address string) (*Telemetry, error) {
	sink, err := newSink(address)
	if err != nil {
		return nil, err
	}

	return NewTelemetryForSink(sink)
}

func NewTelemetryForSink(sink metrics.MetricSink) (*Telemetry, error) {
	_metrics, err := metrics.New(metrics.DefaultConfig(serviceName), sink)
	if err != nil {
		return nil, err
	}
	_metrics.EnableHostname = false

	telemetry := Telemetry{
		Metrics: _metrics,
	}

	return &telemetry, nil
}

func newSink(address string) (metrics.MetricSink, error) {
	if address == "" {
		return &metrics.BlackholeSink{}, nil
	} else {
		return datadog.NewDogStatsdSink(address, noHostName)
	}
}

func (t *Telemetry) Instrument(key []string, err *error) func() {
	start := time.Now()

	return func() {
		latencyInMilliseconds := time.Since(start).Milliseconds()

		t.Metrics.IncrCounter(copyAndAppend(key, calls), 1)
		t.Metrics.SetGauge(copyAndAppend(key, latency), float32(latencyInMilliseconds))

		if *err == nil {
			t.Metrics.IncrCounter(copyAndAppend(key, success), 1)
			t.Metrics.IncrCounter(copyAndAppend(key, failure), 0)
		} else {
			t.Metrics.IncrCounter(copyAndAppend(key, success), 0)
			t.Metrics.IncrCounter(copyAndAppend(key, failure), 1)
		}
	}
}

func copyAndAppend(source []string, values ...string) []string {
	dest := make([]string, len(source), len(source)+len(values))
	copy(dest, source)
	dest = append(dest, values...)
	return dest
}

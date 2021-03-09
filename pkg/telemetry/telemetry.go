package telemetry

import (
	"os"
	"time"

	metrics "github.com/armon/go-metrics"
	"github.com/armon/go-metrics/datadog"
)

const (
	noHostName  = ""
	serviceName = "spiffe-aws-assume-role"

	calls   = "Calls"
	failure = "Failure"
	latency = "Latency"
	success = "Success"
)

type Telemetry struct {
	Metrics  *metrics.Metrics
	hostname string
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
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	return NewTelemetryForSinkAndHostname(sink, hostname)
}

func NewTelemetryForSinkAndHostname(sink metrics.MetricSink, hostname string) (*Telemetry, error) {
	_metrics, err := metrics.New(metrics.DefaultConfig(serviceName), sink)
	if err != nil {
		return nil, err
	}
	_metrics.EnableHostname = false

	telemetry := Telemetry{
		Metrics:  _metrics,
		hostname: hostname,
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

		var labels []metrics.Label
		if len(t.hostname) > 0 {
			labels = []metrics.Label{*newLabel("hostname", t.hostname)}
		}

		t.Metrics.IncrCounterWithLabels(copyAndAppend(key, calls), 1, labels)
		t.Metrics.SetGaugeWithLabels(copyAndAppend(key, latency), float32(latencyInMilliseconds), labels)

		if *err == nil {
			t.Metrics.IncrCounterWithLabels(copyAndAppend(key, success), 1, labels)
			t.Metrics.IncrCounterWithLabels(copyAndAppend(key, failure), 0, labels)
		} else {
			t.Metrics.IncrCounterWithLabels(copyAndAppend(key, success), 0, labels)
			t.Metrics.IncrCounterWithLabels(copyAndAppend(key, failure), 1, labels)
		}
	}
}

func copyAndAppend(source []string, values ...string) []string {
	dest := make([]string, len(source), len(source)+len(values))
	copy(dest, source)
	dest = append(dest, values...)
	return dest
}

func newLabel(name string, value string) *metrics.Label {
	return &metrics.Label{
		Name:  name,
		Value: value,
	}
}

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
	Metrics *metrics.Metrics
	labels  []metrics.Label
}

func (t *Telemetry) AddLabel(name string, value string) {
	t.labels = append(t.labels, metrics.Label{Name: name, Value: value})
}

func NullTelemetry() (*Telemetry, error) {
	return NewTelemetryForSinkAndHostname(&metrics.BlackholeSink{}, noHostName)
}

func MustNullTelemetry() *Telemetry {
	telemetry, err := NullTelemetry()
	if err != nil {
		panic(err)
	}
	return telemetry
}

func NewTelemetry(socket string) (*Telemetry, error) {
	sink, err := newSink(socket)
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
		Metrics: _metrics,
	}
	if len(hostname) > 0 {
		telemetry.AddLabel("hostname", hostname)
	}

	return &telemetry, nil
}

func newSink(socket string) (metrics.MetricSink, error) {
	if socket == "" {
		return &metrics.BlackholeSink{}, nil
	} else {
		return datadog.NewDogStatsdSink(socket, noHostName)
	}
}

func (t *Telemetry) Instrument(baseMetricName []string, err *error) func() {
	start := time.Now()

	return func() {
		latencyInMilliseconds := time.Since(start).Milliseconds()

		t.Metrics.IncrCounterWithLabels(copyAndAppend(baseMetricName, calls), 1, t.labels)
		t.Metrics.SetGaugeWithLabels(copyAndAppend(baseMetricName, latency), float32(latencyInMilliseconds), t.labels)

		if *err == nil {
			t.Metrics.IncrCounterWithLabels(copyAndAppend(baseMetricName, success), 1, t.labels)
			t.Metrics.IncrCounterWithLabels(copyAndAppend(baseMetricName, failure), 0, t.labels)
		} else {
			t.Metrics.IncrCounterWithLabels(copyAndAppend(baseMetricName, success), 0, t.labels)
			t.Metrics.IncrCounterWithLabels(copyAndAppend(baseMetricName, failure), 1, t.labels)
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

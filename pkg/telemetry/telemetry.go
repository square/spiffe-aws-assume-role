package telemetry

import (
	"time"

	metrics "github.com/armon/go-metrics"
)

const (
	noHostName  = ""
	serviceName = "SpiffeAwsAssumeRole"

	calls   = "Calls"
	failure = "Failure"
	latency = "Latency"
	success = "Success"
)

type Telemetry struct {
	sink    CloseableMetricSink
	Metrics *metrics.Metrics
	labels  []metrics.Label
}

var _ Closeable = (*Telemetry)(nil)

func (t *Telemetry) AddLabel(name string, value string) {
	t.labels = append(t.labels, metrics.Label{Name: name, Value: value})
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

func NewTelemetry(socket string) (*Telemetry, error) {
	sink, err := newSink(socket)
	if err != nil {
		return nil, err
	}

	return NewTelemetryForCloseableSink(sink)
}

func NewTelemetryForCloseableSink(sink CloseableMetricSink) (*Telemetry, error) {
	_metrics, err := metrics.New(metrics.DefaultConfig(serviceName), sink)
	if err != nil {
		return nil, err
	}
	_metrics.EnableHostname = false
	_metrics.EnableHostnameLabel = true
	_metrics.EnableServiceLabel = true

	telemetry := Telemetry{
		sink:    sink,
		Metrics: _metrics,
	}

	return &telemetry, nil
}

func NewTelemetryForSink(sink metrics.MetricSink) (*Telemetry, error) {
	return NewTelemetryForCloseableSink(NewCloseableMetricSinkAdapter(sink))
}

func newSink(socket string) (CloseableMetricSink, error) {
	if socket == "" {
		return NewCloseableMetricSinkAdapter(&metrics.BlackholeSink{}), nil
	} else {
		return NewCloseableDogStatsdSink(socket, noHostName)
	}
}

func (t *Telemetry) Close() {
	t.sink.Close()
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

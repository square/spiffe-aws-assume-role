package telemetry

import (
	"time"

	metrics "github.com/armon/go-metrics"
)

const (
	noHostName = ""

	calls   = "calls"
	failure = "failure"
	latency = "latency"
	success = "success"
)

type Telemetry struct {
	sink    CloseableMetricSink
	Metrics *metrics.Metrics
	labels  []metrics.Label
}

type TelemetryOpts struct {
	ServiceName string

	// ServiceName && AsLabel == service name as label
	//
	// ServiceName && !AsLabel == service name as prefix
	ServiceAsLabel bool
	Socket         string
	Labels         map[string]string
}

var _ Closeable = (*Telemetry)(nil)

func (t *Telemetry) AddLabel(name string, value string) {
	t.labels = append(t.labels, metrics.Label{Name: name, Value: value})
}

func NullTelemetry() (*Telemetry, error) {
	return NewTelemetryForSink(&TelemetryOpts{}, &metrics.BlackholeSink{})
}

func MustNullTelemetry() *Telemetry {
	telemetry, err := NullTelemetry()
	if err != nil {
		panic(err)
	}
	return telemetry
}

func NewTelemetry(opts *TelemetryOpts) (*Telemetry, error) {
	sink, err := newSink(opts.Socket)
	if err != nil {
		return nil, err
	}

	return NewTelemetryForCloseableSink(opts, sink)
}

func NewTelemetryForCloseableSink(opts *TelemetryOpts, sink CloseableMetricSink) (*Telemetry, error) {
	_metrics, err := metrics.New(metrics.DefaultConfig(opts.ServiceName), sink)
	if err != nil {
		return nil, err
	}
	_metrics.EnableHostname = false
	_metrics.EnableHostnameLabel = true
	_metrics.EnableServiceLabel = opts.ServiceAsLabel

	telemetry := Telemetry{
		sink:    sink,
		Metrics: _metrics,
	}

	return &telemetry, nil
}

func NewTelemetryForSink(opts *TelemetryOpts, sink metrics.MetricSink) (*Telemetry, error) {
	return NewTelemetryForCloseableSink(opts, NewCloseableMetricSinkAdapter(sink))
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

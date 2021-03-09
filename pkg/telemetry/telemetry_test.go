package telemetry

import (
	"errors"
	"testing"
	"time"

	"github.com/armon/go-metrics"
	"github.com/square/spiffe-aws-assume-role/internal/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var noLabels []metrics.Label = nil

func TestInstrumentCalls(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	telemetry, err := NewTelemetryForSink(&metricSink)
	require.NoError(t, err)

	emitMetrics := telemetry.Instrument([]string{"foo", "bar"}, &err)
	emitMetrics()

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"spiffe-aws-assume-role", "foo", "bar", "Calls"},
		float32(1),
		noLabels)
}

func TestInstrumentLatency(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	telemetry, err := NewTelemetryForSink(&metricSink)
	require.NoError(t, err)

	emitMetrics := telemetry.Instrument([]string{"foo", "bar"}, &err)
	time.Sleep(time.Second * 1)
	emitMetrics()

	metricSink.AssertCalled(t, "SetGaugeWithLabels",
		[]string{"spiffe-aws-assume-role", "foo", "bar", "Latency"},
		mock.MatchedBy(greaterThanOrEqualFloat32(1000)),
		noLabels)
}

func TestInstrumentSuccess(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	telemetry, err := NewTelemetryForSink(&metricSink)
	require.NoError(t, err)

	methodThatSucceeds(telemetry)

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"spiffe-aws-assume-role", "foo", "bar", "Success"},
		float32(1),
		noLabels)
	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"spiffe-aws-assume-role", "foo", "bar", "Failure"},
		float32(0),
		noLabels)
}

func TestInstrumentFailure(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	telemetry, err := NewTelemetryForSink(&metricSink)
	require.NoError(t, err)

	methodThatFails(telemetry)

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"spiffe-aws-assume-role", "foo", "bar", "Failure"},
		float32(1),
		noLabels)
	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"spiffe-aws-assume-role", "foo", "bar", "Success"},
		float32(0),
		noLabels)
}

// These next two methods are intended to simulate typical usage patterns

func methodThatSucceeds(t *Telemetry) (err error) {
	emitMetrics := t.Instrument([]string{"foo", "bar"}, &err)
	defer emitMetrics()

	return nil
}

func methodThatFails(t *Telemetry) (err error) {
	emitMetrics := t.Instrument([]string{"foo", "bar"}, &err)
	defer emitMetrics()

	return errors.New("bar")
}

func greaterThanOrEqualFloat32(y float32) func(float32) bool {
	return func(x float32) bool {
		return x >= y
	}
}

func allowAllCalls(metricSink *mocks.MetricSink) {
	// Without any expected calls the mock will fail fast. To prevent this we add in some generic expectations
	// that will match anything. Also note that there's a background thread emitting runtime metrics (memory,
	// goroutine count, etc.) that we don't control so we can't explicitly list out every expected call.
	metricSink.On("IncrCounterWithLabels", mock.Anything, mock.Anything, mock.Anything).Return()
	metricSink.On("SetGaugeWithLabels", mock.Anything, mock.Anything, mock.Anything).Return()
}

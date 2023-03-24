package telemetry

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/armon/go-metrics"
	"github.com/google/uuid"
	"github.com/square/spiffe-aws-assume-role/internal/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var anyLabels string = mock.Anything

func TestInstrumentCalls(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	opts := &TelemetryOpts{}
	telemetry, err := NewTelemetryForSink(opts, &metricSink)
	require.NoError(t, err)

	emitMetrics := telemetry.Instrument([]string{"foo", "bar"}, &err)
	emitMetrics()

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"foo", "bar", "Calls"},
		float32(1),
		anyLabels)
}

func TestInstrumentLatency(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	opts := &TelemetryOpts{}
	telemetry, err := NewTelemetryForSink(opts, &metricSink)
	require.NoError(t, err)

	emitMetrics := telemetry.Instrument([]string{"foo", "bar"}, &err)
	time.Sleep(time.Second * 1)
	emitMetrics()

	metricSink.AssertCalled(t, "SetGaugeWithLabels",
		[]string{"foo", "bar", "Latency"},
		mock.MatchedBy(greaterThanOrEqualFloat32(1000)),
		anyLabels)
}

func TestInstrumentSuccess(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	opts := &TelemetryOpts{}
	telemetry, err := NewTelemetryForSink(opts, &metricSink)
	require.NoError(t, err)

	require.NoError(t, methodThatSucceeds(telemetry))

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"foo", "bar", "Success"},
		float32(1),
		anyLabels)
	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"foo", "bar", "Failure"},
		float32(0),
		anyLabels)
}

func TestInstrumentFailure(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)

	opts := &TelemetryOpts{}
	telemetry, err := NewTelemetryForSink(opts, &metricSink)
	require.NoError(t, err)

	require.Error(t, methodThatFails(telemetry))

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"foo", "bar", "Failure"},
		float32(1),
		anyLabels)
	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"foo", "bar", "Success"},
		float32(0),
		anyLabels)
}

func TestInstrumentBuiltInLabels(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)
	serviceName := "spiffe_aws_assume_role"

	opts := &TelemetryOpts{ServiceName: serviceName}
	telemetry, err := NewTelemetryForSink(opts, &metricSink)
	require.NoError(t, err)

	telemetry.Instrument(nil, &err)()

	hostname, err := os.Hostname()
	require.NoError(t, err)
	hostnameLabel := metrics.Label{
		Name:  "host",
		Value: hostname,
	}

	serviceNameLabel := metrics.Label{
		Name:  "service",
		Value: serviceName,
	}

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"Calls"},
		float32(1),
		[]metrics.Label{hostnameLabel, serviceNameLabel})
}

func TestInstrumentCustomLabel(t *testing.T) {
	metricSink := mocks.MetricSink{}
	allowAllCalls(&metricSink)
	serviceName := "spiffe_aws_assume_role"

	opts := &TelemetryOpts{ServiceName: serviceName}
	telemetry, err := NewTelemetryForSink(opts, &metricSink)
	require.NoError(t, err)

	labelName := uuid.New().String()
	labelValue := uuid.New().String()
	telemetry.AddLabel(labelName, labelValue)

	telemetry.Instrument(nil, &err)()

	customLabel := metrics.Label{
		Name:  labelName,
		Value: labelValue,
	}

	hostname, err := os.Hostname()
	require.NoError(t, err)
	hostnameLabel := metrics.Label{
		Name:  "host",
		Value: hostname,
	}

	serviceNameLabel := metrics.Label{
		Name:  "service",
		Value: serviceName,
	}

	metricSink.AssertCalled(t, "IncrCounterWithLabels",
		[]string{"Calls"},
		float32(1),
		[]metrics.Label{customLabel, hostnameLabel, serviceNameLabel})
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

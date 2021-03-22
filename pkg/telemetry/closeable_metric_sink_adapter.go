package telemetry

import "github.com/armon/go-metrics"

type CloseableMetricSinkAdapter struct {
	delegate metrics.MetricSink
}

var _ CloseableMetricSink = (*CloseableMetricSinkAdapter)(nil)

func NewCloseableMetricSinkAdapter(delegate metrics.MetricSink) *CloseableMetricSinkAdapter {
	return &CloseableMetricSinkAdapter{
		delegate: delegate,
	}
}

func (w *CloseableMetricSinkAdapter) Close() {}

func (w *CloseableMetricSinkAdapter) SetGauge(key []string, val float32) {
	w.delegate.SetGauge(key, val)
}

func (w *CloseableMetricSinkAdapter) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {
	w.delegate.SetGaugeWithLabels(key, val, labels)
}

func (w *CloseableMetricSinkAdapter) EmitKey(key []string, val float32) {
	w.delegate.EmitKey(key, val)
}

func (w *CloseableMetricSinkAdapter) IncrCounter(key []string, val float32) {
	w.delegate.IncrCounter(key, val)
}

func (w *CloseableMetricSinkAdapter) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {
	w.delegate.IncrCounterWithLabels(key, val, labels)
}

func (w *CloseableMetricSinkAdapter) AddSample(key []string, val float32) {
	w.delegate.AddSample(key, val)
}

func (w *CloseableMetricSinkAdapter) AddSampleWithLabels(key []string, val float32, labels []metrics.Label) {
	w.delegate.AddSampleWithLabels(key, val, labels)
}

package telemetry

import "github.com/armon/go-metrics"

type CloseableMetricSink interface {
	Closeable
	metrics.MetricSink
}

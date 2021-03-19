package telemetry

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/armon/go-metrics"
)

// This class is just a copy of the original DogStatsdSink with an additional Close() method.

type CloseableDogStatsdSink struct {
	client            *statsd.Client
	hostName          string
	propagateHostname bool
}

var _ CloseableMetricSink = (*CloseableDogStatsdSink)(nil)

func NewCloseableDogStatsdSink(addr string, hostName string) (*CloseableDogStatsdSink, error) {
	client, err := statsd.New(addr)
	if err != nil {
		return nil, err
	}
	sink := &CloseableDogStatsdSink{
		client:            client,
		hostName:          hostName,
		propagateHostname: false,
	}
	return sink, nil
}

func (s *CloseableDogStatsdSink) Close() {
	_ = s.client.Close()
}

func (s *CloseableDogStatsdSink) SetTags(tags []string) {
	s.client.Tags = tags
}

func (s *CloseableDogStatsdSink) EnableHostNamePropagation() {
	s.propagateHostname = true
}

func (s *CloseableDogStatsdSink) flattenKey(parts []string) string {
	joined := strings.Join(parts, ".")
	return strings.Map(sanitize, joined)
}

func sanitize(r rune) rune {
	switch r {
	case ':':
		fallthrough
	case ' ':
		return '_'
	default:
		return r
	}
}

func (s *CloseableDogStatsdSink) parseKey(key []string) ([]string, []metrics.Label) {
	// Since DogStatsd supports dimensionality via tags on metric keys, this sink's approach is to splice the hostname out of the key in favor of a `host` tag
	// The `host` tag is either forced here, or set downstream by the DogStatsd server

	var labels []metrics.Label
	hostName := s.hostName

	// Splice the hostname out of the key
	for i, el := range key {
		if el == hostName {
			key = append(key[:i], key[i+1:]...)
			break
		}
	}

	if s.propagateHostname {
		labels = append(labels, metrics.Label{
			Name:  "host",
			Value: hostName,
		})
	}
	return key, labels
}

func (s *CloseableDogStatsdSink) SetGauge(key []string, val float32) {
	s.SetGaugeWithLabels(key, val, nil)
}

func (s *CloseableDogStatsdSink) IncrCounter(key []string, val float32) {
	s.IncrCounterWithLabels(key, val, nil)
}

func (s *CloseableDogStatsdSink) EmitKey(key []string, val float32) {}

func (s *CloseableDogStatsdSink) AddSample(key []string, val float32) {
	s.AddSampleWithLabels(key, val, nil)
}

func (s *CloseableDogStatsdSink) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {
	flatKey, tags := s.getFlatkeyAndCombinedLabels(key, labels)
	rate := 1.0
	_ = s.client.Gauge(flatKey, float64(val), tags, rate)
}

func (s *CloseableDogStatsdSink) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {
	flatKey, tags := s.getFlatkeyAndCombinedLabels(key, labels)
	rate := 1.0
	_ = s.client.Count(flatKey, int64(val), tags, rate)
}

func (s *CloseableDogStatsdSink) AddSampleWithLabels(key []string, val float32, labels []metrics.Label) {
	flatKey, tags := s.getFlatkeyAndCombinedLabels(key, labels)
	rate := 1.0
	_ = s.client.TimeInMilliseconds(flatKey, float64(val), tags, rate)
}

func (s *CloseableDogStatsdSink) getFlatkeyAndCombinedLabels(key []string, labels []metrics.Label) (string, []string) {
	key, parsedLabels := s.parseKey(key)
	flatKey := s.flattenKey(key)
	labels = append(labels, parsedLabels...)

	var tags []string
	for _, label := range labels {
		label.Name = strings.Map(sanitize, label.Name)
		label.Value = strings.Map(sanitize, label.Value)
		if label.Value != "" {
			tags = append(tags, fmt.Sprintf("%s:%s", label.Name, label.Value))
		} else {
			tags = append(tags, label.Name)
		}
	}

	return flatKey, tags
}

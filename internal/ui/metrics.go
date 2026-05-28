package ui

import (
	"github.com/keylatch/keylatch/internal/metrics"
)

// MetricsCollector is an alias for metrics.MetricsCollector.
// Kept for backward compatibility with existing callers in this package
// and in internal/gateway/server.go which imports ui.MetricsCollector.
type MetricsCollector = metrics.MetricsCollector

// NewMetricsCollector creates a new MetricsCollector.
func NewMetricsCollector() *MetricsCollector {
	return metrics.New()
}

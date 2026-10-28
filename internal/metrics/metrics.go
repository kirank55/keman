package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Registry      *prometheus.Registry
	Requests      *prometheus.CounterVec
	Duration      *prometheus.HistogramVec
	EventsDropped prometheus.Counter
	EventsSkipped prometheus.Counter
	FlushFailures prometheus.Counter
	AlertsSent    prometheus.Counter
	AlertsFailed  prometheus.Counter
	SpendDegraded prometheus.Gauge
	QueueDepth    prometheus.Gauge
}

func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keman_proxy_requests_total",
			Help: "Proxy requests by result code and profile.",
		}, []string{"code", "profile"}),
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keman_proxy_duration_seconds",
			Help:    "Time spent inside the proxy, including the upstream round trip.",
			Buckets: []float64{.0005, .001, .002, .003, .005, .01, .025, .05, .1, .25, 1},
		}, []string{"profile"}),
		EventsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keman_events_dropped_total",
			Help: "Events dropped because the queue was full.",
		}),
		EventsSkipped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keman_events_skipped_total",
			Help: "Events whose detection or storage step failed open.",
		}),
		FlushFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keman_spend_flush_failures_total",
			Help: "Spend counter flushes that failed.",
		}),
		AlertsSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keman_alerts_sent_total",
			Help: "Alert deliveries that succeeded.",
		}),
		AlertsFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keman_alerts_failed_total",
			Help: "Alert deliveries that failed.",
		}),
		SpendDegraded: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "keman_spend_flush_degraded",
			Help: "1 when spend caps are fail-closed because flushes have been failing.",
		}),
		QueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "keman_event_queue_depth",
			Help: "Events waiting to be stored.",
		}),
	}
	reg.MustRegister(m.Requests, m.Duration, m.EventsDropped, m.EventsSkipped, m.FlushFailures, m.AlertsSent, m.AlertsFailed, m.SpendDegraded, m.QueueDepth)
	return m
}

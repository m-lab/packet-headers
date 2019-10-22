package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics for general use. All metrics should start with pcap_ to indicate that
// they come from the packet-header system.
var (
	MissedPackets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pcap_missed_packets_total",
			Help: "How many packets were captured and thrown away.  It is bad if packets are missed and saverstate is not 'stopped'.",
		},
		[]string{"saverstate"},
	)
	FlowsOpened = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_flow_save_starts_total",
			Help: "How many flows have started to be saved.",
		},
	)
	FlowsClosed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_flow_save_ends_total",
			Help: "How many flows have been terminated and saved.",
		},
	)
	FlowSaveErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pcap_flow_save_errors_total",
			Help: "How many flows have not been saved due to errors",
		},
		[]string{"reason"},
	)
	UnknownFlowsClosed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_unknown_flows_closed_total",
			Help: "How many flows have been closed that we never saw opened.",
		},
	)
)

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
	UnknownFlowsClosed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_unknown_flows_closed_total",
			Help: "How many flows have been closed that we never saw opened.",
		},
	)

	// Savers are internal data structures each with a signle associated
	// goroutine, that are allocated and run once for each connection. Their
	// start and stop is counted in SaversStarted and SaversStopped, their
	// errors in SaverErrors, and the current state of all running Savers is in
	// SaverCount.
	SaversStarted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_saver_starts_total",
			Help: "How many flows have started to be saved.",
		},
	)
	SaversStopped = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_saver_stops_total",
			Help: "How many flows have been terminated and saved.",
		},
	)
	SaverErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pcap_saver_errors_total",
			Help: "How many flows have not been saved by a saver due to errors",
		},
		[]string{"reason"},
	)
	SaverCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pcap_saver_states",
			Help: "How many savers are currently in each state",
		},
		[]string{"state"},
	)

// TODO: Create histograms for:
//
// time spent by savers in unknown state
// amount of data buffered before being "opened". (maybe - how do you poll a channel for its buffer usage?)
//
// TODO: Create histograms for:
//
// p0 - time PH first seeing a flow
// t0 - time tcpinfo sees a flow (Timestamp of event)
// p1 - time PH gets open signal from tcpinfo.
//
// avg(p0 - t0) expected to be a small constant
// avg(p1 - t0) expected to be much less than 3sec
//
// ^ Those avgs seem like sensitive SLIs.

)

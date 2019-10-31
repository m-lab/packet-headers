// Package metrics is the central storage lcoation for all program metrics.
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
			Help: "How many packets were captured and thrown away.  This should always be zero.",
		},
		[]string{"saverstate"},
	)
	MissedUUIDs = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pcap_missed_uuids_total",
			Help: "How many uuid notifications were ignored.  This should always be zero.",
		},
		[]string{"saverstate"},
	)

	// Savers are internal data structures each with a single associated
	// goroutine, that are allocated and run once for each connection. The start
	// and stop of that goroutine is counted in SaversStarted and SaversStopped,
	// their errors in SaverErrors, and the current state of all running Savers
	// is in SaverCount.
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

	// Demuxer metrics keep track of the state of the system that sends packets
	// to a particular saver.
	DemuxerBadPacket = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_demuxer_bad_packets_total",
			Help: "How many packets has the demuxer received that it could not process.  This should always be zero.",
		},
	)
	DemuxerGCLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "pcap_demuxer_gc_latency_seconds",
			Help:    "How long has each GC call taken, and how many GC calls have there been.",
			Buckets: prometheus.ExponentialBuckets(.000001, 2, 20), // Start at 1 microsecond and work our way up to 1 second.
		},
	)
	DemuxerUUIDCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "pcap_demuxer_uuids_total",
			Help: "How many UUIDs has the demuxer been told about. Should match pcap_saver_starts_total very closely",
		},
	)

	BadEventsFromTCPInfo = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pcap_tcpinfohandler_bad_events_total",
			Help: "How many unparseable events have been sent from tcp-info. This should always be zero.",
		},
		[]string{"reason"},
	)

	InterfacesBeingCaptured = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "pcap_muxer_interfaces_with_captures",
			Help: "How many interfaces currently have a packet capture running on them, according to the muxer.",
		},
	)

// TODO(https://github.com/m-lab/packet-headers/issues/5) Create some histograms for SLIs
)

package metrics

import (
	"testing"

	"github.com/m-lab/go/prometheusx/promtest"
)

func TestMetrics(t *testing.T) {
	MissedPackets.WithLabelValues("x").Inc()
	FlowSaveErrors.WithLabelValues("x").Inc()
	promtest.LintMetrics(t)
}

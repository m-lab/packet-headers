package metrics

import (
	"testing"

	"github.com/m-lab/go/prometheusx/promtest"
)

func TestMetrics(t *testing.T) {
	MissedPackets.WithLabelValues("x").Inc()
	SaverErrors.WithLabelValues("x").Inc()
	SaverCount.WithLabelValues("x").Inc()
	promtest.LintMetrics(t)
}

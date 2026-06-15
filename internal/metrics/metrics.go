// Package metrics exposes Prometheus metrics for the control plane at /metrics.
package metrics

import (
	"net/http"

	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the registry and the counters the server increments directly.
type Metrics struct {
	reg    *prometheus.Registry
	enroll *prometheus.CounterVec
}

// New builds a Metrics with a dynamic collector reading live state from the peer
// store and the tenant store at scrape time.
func New(peers *store.Store, tenants *tenant.Store) *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		enroll: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "claimward_enrollments_total",
			Help: "Total number of successful device enrollments.",
		}, []string{"tenant"}),
	}
	m.reg.MustRegister(m.enroll)
	m.reg.MustRegister(newCollector(peers, tenants))
	return m
}

// EnrollInc records an enrollment for a tenant.
func (m *Metrics) EnrollInc(tenantID string) { m.enroll.WithLabelValues(tenantID).Inc() }

// Handler serves the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

type collector struct {
	peers   *store.Store
	tenants *tenant.Store

	tenantsDesc *prometheus.Desc
	peersDesc   *prometheus.Desc
	watchDesc   *prometheus.Desc
	serialDesc  *prometheus.Desc
}

func newCollector(peers *store.Store, tenants *tenant.Store) *collector {
	return &collector{
		peers:   peers,
		tenants: tenants,
		tenantsDesc: prometheus.NewDesc("claimward_tenants", "Number of configured tenants.", nil, nil),
		peersDesc:   prometheus.NewDesc("claimward_active_peers", "Number of currently enrolled peers.", nil, nil),
		watchDesc:   prometheus.NewDesc("claimward_route_watchers", "Number of active gRPC route watchers.", nil, nil),
		serialDesc:  prometheus.NewDesc("claimward_tenant_route_serial", "Current route serial per tenant.", []string{"tenant"}, nil),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tenantsDesc
	ch <- c.peersDesc
	ch <- c.watchDesc
	ch <- c.serialDesc
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	tenants := c.tenants.List()
	ch <- prometheus.MustNewConstMetric(c.tenantsDesc, prometheus.GaugeValue, float64(len(tenants)))
	ch <- prometheus.MustNewConstMetric(c.peersDesc, prometheus.GaugeValue, float64(len(c.peers.List())))
	ch <- prometheus.MustNewConstMetric(c.watchDesc, prometheus.GaugeValue, float64(c.tenants.WatcherCount()))
	for _, t := range tenants {
		ch <- prometheus.MustNewConstMetric(c.serialDesc, prometheus.GaugeValue, float64(t.Serial), t.ID)
	}
}

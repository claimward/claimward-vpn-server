package config

import "testing"

// /metrics names every tenant: it is served on loopback unless told otherwise.
func TestMetricsAddrDefaultsToLoopback(t *testing.T) {
	baseEnv(t)
	t.Setenv("METRICS_ADDR", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MetricsAddr != "127.0.0.1:9090" {
		t.Errorf("MetricsAddr = %q, want the loopback default", c.MetricsAddr)
	}
	t.Setenv("METRICS_ADDR", "10.0.0.5:9100")
	if c, err = Load(); err != nil || c.MetricsAddr != "10.0.0.5:9100" {
		t.Errorf("METRICS_ADDR not honoured: %v %v", c, err)
	}
}

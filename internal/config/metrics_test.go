package config

import "testing"

// /metrics names every tenant and a fixed port clashes with other services:
// nothing is served unless METRICS_ADDR is set.
func TestMetricsAreOffUnlessAddressed(t *testing.T) {
	baseEnv(t)
	t.Setenv("METRICS_ADDR", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MetricsAddr != "" {
		t.Errorf("MetricsAddr = %q, want none by default", c.MetricsAddr)
	}
	t.Setenv("METRICS_ADDR", "10.0.0.5:9100")
	if c, err = Load(); err != nil || c.MetricsAddr != "10.0.0.5:9100" {
		t.Errorf("METRICS_ADDR not honoured: %v %v", c, err)
	}
}

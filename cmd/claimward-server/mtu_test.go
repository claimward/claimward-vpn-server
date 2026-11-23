package main

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/config"
)

func TestApplyTunnelMTU(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	type call struct {
		name string
		mtu  int
	}
	for _, c := range []struct {
		name     string
		cfg      config.Config
		uplink   int
		setErr   error
		wantMTU  int
		wantCall *call
		wantErr  bool
	}{
		{"explicit wins over the uplink", config.Config{TunnelMTU: 1300, WGInterface: "wg0"}, 1450, nil, 1300, &call{"wg0", 1300}, false},
		{"derived from a 1450 uplink", config.Config{WGInterface: "wg0"}, 1450, nil, 1370, &call{"wg0", 1370}, false},
		{"unknown uplink is the default", config.Config{WGInterface: "wg0"}, 0, nil, 1420, &call{"wg0", 1420}, false},
		{"dry run applies nothing", config.Config{DryRun: true, WGInterface: "wg0"}, 1450, nil, 1370, nil, false},
		{"a failed set stops the start", config.Config{WGInterface: "wg0"}, 1500, errors.New("EPERM"), 1420, &call{"wg0", 1420}, true},
	} {
		var got *call
		cfg := c.cfg
		err := applyTunnelMTU(&cfg, func() int { return c.uplink }, func(n string, m int) error {
			got = &call{n, m}
			return c.setErr
		}, log)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.wantErr)
		}
		if cfg.TunnelMTU != c.wantMTU {
			t.Errorf("%s: cfg.TunnelMTU = %d, want %d", c.name, cfg.TunnelMTU, c.wantMTU)
		}
		if (got == nil) != (c.wantCall == nil) || (got != nil && *got != *c.wantCall) {
			t.Errorf("%s: set called with %v, want %v", c.name, got, c.wantCall)
		}
	}
}

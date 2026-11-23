package tenant

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Bounds on a tenants file: it is read once at start, from an operator's
// file, but it becomes kernel rules.
const (
	maxFileBytes   = 4 << 20
	maxFileTenants = 1024
)

// ParseFile reads a tenants file: a JSON array of tenants, each with an
// optional "policy" (see internal/policy). Unknown fields, trailing data and
// an invalid policy are refused.
//
//	[
//	  {"id": "default", "policy": [{"cidr": "10.20.0.5/32", "proto": "tcp", "ports": [445]}]},
//	  {"id": "chem", "groups": ["chem"], "policy": [...]}
//	]
func ParseFile(data []byte) ([]Tenant, error) {
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("tenants file is larger than %d bytes", maxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var ts []Tenant
	if err := dec.Decode(&ts); err != nil {
		return nil, fmt.Errorf("tenants file: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("tenants file: trailing data")
	}
	if len(ts) > maxFileTenants {
		return nil, fmt.Errorf("tenants file has %d tenants, the limit is %d", len(ts), maxFileTenants)
	}
	for i := range ts {
		if err := ts[i].normalize(); err != nil {
			return nil, fmt.Errorf("tenant %d (%q): %w", i, ts[i].ID, err)
		}
	}
	return ts, nil
}

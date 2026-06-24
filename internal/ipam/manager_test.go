package ipam

import (
	"net"
	"testing"
)

func TestManagerAllocatesFromTenantSubnet(t *testing.T) {
	m, err := NewManager("10.80.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	ip, err := m.Allocate("test", "10.90.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, testNet, _ := net.ParseCIDR("10.90.0.0/24")
	if !testNet.Contains(ip) {
		t.Fatalf("test peer got %s, want an address in 10.90.0.0/24", ip)
	}
	// First host is the gateway, so the first peer gets the second host.
	if ip.String() != "10.90.0.2" {
		t.Fatalf("got %s, want 10.90.0.2", ip)
	}
}

func TestManagerKeepsTenantPoolsSeparate(t *testing.T) {
	m, _ := NewManager("10.80.0.0/24")
	a, _ := m.Allocate("a", "10.90.0.0/24")
	b, _ := m.Allocate("b", "10.91.0.0/24")
	if a.String() != "10.90.0.2" || b.String() != "10.91.0.2" {
		t.Fatalf("pools overlap: a=%s b=%s", a, b)
	}
}

func TestManagerFallbackPoolShared(t *testing.T) {
	m, _ := NewManager("10.80.0.0/24")
	// Tenants without a subnet share the fallback pool, so addresses must not
	// collide across them.
	a, _ := m.Allocate("a", "")
	b, _ := m.Allocate("b", "")
	if a.Equal(b) {
		t.Fatalf("fallback handed out %s twice", a)
	}
	_, fb, _ := net.ParseCIDR("10.80.0.0/24")
	if !fb.Contains(a) || !fb.Contains(b) {
		t.Fatalf("fallback addresses outside pool: a=%s b=%s", a, b)
	}
}

func TestManagerReleaseReturnsToTenantPool(t *testing.T) {
	m, _ := NewManager("10.80.0.0/24")
	ip, _ := m.Allocate("test", "10.90.0.0/24")
	m.Release("test", ip)
	again, _ := m.Allocate("test", "10.90.0.0/24")
	if !ip.Equal(again) {
		t.Fatalf("released %s but next alloc was %s", ip, again)
	}
}

func TestManagerReserveKeepsExistingIP(t *testing.T) {
	m, _ := NewManager("10.80.0.0/24")
	want := net.ParseIP("10.90.0.7")
	if !m.Reserve("test", "10.90.0.0/24", want) {
		t.Fatal("reserve failed")
	}
	// The reserved address must not be handed out again.
	got, _ := m.Allocate("test", "10.90.0.0/24")
	if got.Equal(want) {
		t.Fatalf("allocated the reserved address %s", want)
	}
}

func TestManagerRebuildsPoolWhenSubnetChanges(t *testing.T) {
	m, _ := NewManager("10.80.0.0/24")
	old, _ := m.Allocate("test", "10.90.0.0/24")
	// Tenant subnet changes; the pool is rebuilt for the new CIDR.
	got, err := m.Allocate("test", "10.92.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, newNet, _ := net.ParseCIDR("10.92.0.0/24")
	if !newNet.Contains(got) {
		t.Fatalf("after subnet change got %s, want in 10.92.0.0/24 (old=%s)", got, old)
	}
}

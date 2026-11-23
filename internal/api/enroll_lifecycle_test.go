package api

// Regression tests for the address lifecycle of POST /enroll (2026-11-23
// security audit): per-subject cap, concurrent enrollment, failed re-enroll.

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newKey(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func assigned(t *testing.T, body []byte) string {
	t.Helper()
	var r protocol.EnrollResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	ip, _, err := net.ParseCIDR(r.AssignedIP)
	if err != nil {
		t.Fatalf("assigned %q: %v", r.AssignedIP, err)
	}
	return ip.String()
}

// Claim 1: one identity can take the whole pool.
func TestOneSubjectCannotExhaustThePool(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()
	n := 0
	for i := 0; i < 300; i++ {
		w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: newKey(t)})
		if w.Code != 200 {
			break
		}
		n++
	}
	w := call(t, h, protocol.PathEnroll, "bob", protocol.EnrollRequest{PublicKey: newKey(t)})
	if w.Code != 200 {
		t.Errorf("alice enrolled %d devices; bob then got %d %s", n, w.Code, w.Body)
	}
}

// barrierGW blocks every AddPeer until two have arrived, forcing two
// concurrent enrollments of one key to interleave between Get and Put.
type barrierGW struct {
	wg.Gateway
	wg sync.WaitGroup
}

func (g *barrierGW) AddPeer(pub wgtypes.Key, ip net.IP) error {
	g.wg.Done()
	// Once enrollments are serialised the second never arrives: give up
	// waiting for it rather than deadlock.
	done := make(chan struct{})
	go func() { g.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
	}
	return nil
}

// Claim 3: two concurrent first enrollments of one key leak an address.
func TestConcurrentEnrollOfOneKeyLeaksNoAddress(t *testing.T) {
	s, st := newServer(t)
	g := &barrierGW{Gateway: s.gw}
	g.wg.Add(2)
	s.gw = g
	h := s.Handler()
	key := newKey(t)
	ips := make([]string, 2)
	var done sync.WaitGroup
	for i := range ips {
		done.Add(1)
		go func() {
			defer done.Done()
			w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: key})
			if w.Code == 200 {
				ips[i] = assigned(t, w.Body.Bytes())
			}
		}()
	}
	done.Wait()
	held := st.Get(key).IP.String()
	for _, ip := range ips {
		if ip == "" || ip == held {
			continue
		}
		if !s.alloc.Reserve(net.ParseIP(ip)) {
			t.Errorf("responses %v, store holds %s: %s is allocated and owned by nobody (leaked)", ips, held, ip)
		}
	}
}

// failGW fails AddPeer when told to.
type failGW struct {
	wg.Gateway
	fail bool
}

func (g *failGW) AddPeer(pub wgtypes.Key, ip net.IP) error {
	if g.fail {
		return errors.New("netlink: boom")
	}
	return g.Gateway.AddPeer(pub, ip)
}

// Claim 5: a failed re-enroll releases the address the peer still holds.
func TestFailedReenrollKeepsTheAddress(t *testing.T) {
	s, st := newServer(t)
	g := &failGW{Gateway: s.gw}
	s.gw = g
	h := s.Handler()
	key := newKey(t)
	if w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: key}); w.Code != 200 {
		t.Fatal(w.Body)
	}
	aliceIP := st.Get(key).IP.String()
	g.fail = true
	if w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: key}); w.Code != 500 {
		t.Fatalf("re-enroll with a failing gateway: %d", w.Code)
	}
	g.fail = false
	w := call(t, h, protocol.PathEnroll, "bob", protocol.EnrollRequest{PublicKey: newKey(t)})
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	if bobIP := assigned(t, w.Body.Bytes()); bobIP == aliceIP && st.Get(key) != nil {
		t.Errorf("bob was given %s, which alice's still-enrolled peer holds", bobIP)
	}
}

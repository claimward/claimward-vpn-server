package privsep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/claimward/claimward-vpn-server/internal/fw"
)

// MaxRefusals is how many refused requests a session may cost before the
// parent ends it: a child that keeps asking for what it may not have is not
// the child that was started.
const MaxRefusals = 16

// ErrTooManyRefusals ends a session that kept asking for what is not allowed.
var ErrTooManyRefusals = errors.New("privsep: the child made too many refused requests")

// Backend is what the parent does, once a request has been judged allowed. The
// real one drives the kernel; tests drive a fake.
type Backend interface {
	AddPeer(key [KeySize]byte, ip netip.Addr) error
	RemovePeer(key [KeySize]byte) error
	// Sweep removes the peers a previous run left, and says how many.
	Sweep() (int, error)
	// SetTunnelMTU applies mtu to the interface (0 derives it from the uplink)
	// and returns the MTU in force.
	SetTunnelMTU(mtu int) (int, error)
	// ApplyTenants installs the firewall of the tenants, clamping the MSS to
	// mtu, the tunnel MTU in force.
	ApplyTenants(ts []fw.Tenant, mtu int) error
}

// Server is the parent's half: it reads requests, refuses what is not
// allowed, and does the rest. One Server serves one session.
type Server struct {
	B      Backend
	Limits Limits
	Log    *slog.Logger

	mu       sync.Mutex
	added    map[[KeySize]byte]netip.Addr // the peers this session added: the only ones it may remove
	byIP     map[netip.Addr][KeySize]byte
	mtu      int  // 0 until SetMTU
	swept    bool // Sweep has run
	refusals int
}

// refusal is a request the parent will not honour.
type refusal struct{ err error }

func (r refusal) Error() string { return r.err.Error() }

func refuse(format string, a ...any) error { return refusal{fmt.Errorf(format, a...)} }

// Serve reads requests from rw until it ends. It returns nil when the child
// closed the socket at a frame boundary, and an error when the stream broke
// (a *ProtocolError), when the child exceeded MaxRefusals, or when the
// transport failed: in all those cases the caller ends the child.
func (s *Server) Serve(rw io.ReadWriter) error {
	for {
		t, body, err := ReadFrame(rw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if t&ReplyFlag != 0 {
			return protoErr("a reply (type %d) arrived where a request belongs", uint8(t))
		}
		payload, herr := s.handle(t, body)
		status, out := StatusOK, payload
		var ref refusal
		switch {
		case herr == nil:
		case errors.As(herr, &ref):
			status, out = StatusRefused, truncate(ref.Error())
			s.Log.Warn("privsep: request refused", "type", t.String(), "reason", ref.Error())
			s.mu.Lock()
			s.refusals++
			over := s.refusals >= MaxRefusals
			s.mu.Unlock()
			if over {
				_ = WriteFrame(rw, t|ReplyFlag, append([]byte{status}, out...))
				return ErrTooManyRefusals
			}
		default:
			status, out = StatusFailed, truncate(herr.Error())
		}
		if err := WriteFrame(rw, t|ReplyFlag, append([]byte{status}, out...)); err != nil {
			return err
		}
	}
}

func truncate(s string) []byte {
	if len(s) > maxMessage {
		s = s[:maxMessage]
	}
	return []byte(s)
}

// handle decodes, judges and performs one request. A refusal is returned as a
// refusal{}; any other error is the kernel's.
func (s *Server) handle(t Type, body []byte) ([]byte, error) {
	req, err := Decode(t, body)
	if err != nil {
		return nil, refuse("%v", err)
	}
	if err := s.Limits.Check(req); err != nil {
		return nil, refuse("%v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m := req.(type) {
	case AddPeer:
		if other, ok := s.byIP[m.IP]; ok && other != m.Key {
			return nil, refuse("add-peer: address %v belongs to another peer", m.IP)
		}
		if err := s.B.AddPeer(m.Key, m.IP); err != nil {
			return nil, err
		}
		if old, ok := s.added[m.Key]; ok {
			delete(s.byIP, old) // a replaced peer frees its old address
		}
		s.added[m.Key] = m.IP
		s.byIP[m.IP] = m.Key
		return nil, nil
	case RemovePeer:
		ip, ok := s.added[m.Key]
		if !ok {
			return nil, refuse("remove-peer: not a peer this session added")
		}
		if err := s.B.RemovePeer(m.Key); err != nil {
			return nil, err
		}
		delete(s.added, m.Key)
		delete(s.byIP, ip)
		return nil, nil
	case Sweep:
		if s.swept || len(s.added) != 0 {
			return nil, refuse("sweep: only once, before any peer is added")
		}
		s.swept = true
		n, err := s.B.Sweep()
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint32(nil, uint32(n)), nil
	case SetMTU:
		if s.mtu != 0 {
			return nil, refuse("set-mtu: the tunnel MTU is already set")
		}
		got, err := s.B.SetTunnelMTU(int(m.MTU))
		if err != nil {
			return nil, err
		}
		if got < s.Limits.MinMTU || got > s.Limits.MaxMTU {
			return nil, fmt.Errorf("set-mtu: the tunnel MTU in force, %d, is outside %d to %d", got, s.Limits.MinMTU, s.Limits.MaxMTU)
		}
		s.mtu = got
		return binary.BigEndian.AppendUint32(nil, uint32(got)), nil
	case Apply:
		if s.mtu == 0 {
			return nil, refuse("apply-tenants: the tunnel MTU is not set yet")
		}
		return nil, s.B.ApplyTenants(m.Tenants, s.mtu)
	}
	return nil, refuse("request %T is not in the allowlist", req)
}

// NewServer is a Server with its state initialised.
func NewServer(b Backend, l Limits, log *slog.Logger) *Server {
	return &Server{B: b, Limits: l, Log: log, added: map[[KeySize]byte]netip.Addr{}, byIP: map[netip.Addr][KeySize]byte{}}
}

// Teardown removes every peer this session added, when the child is gone and
// nobody is left to reap them. The firewall stays as it is: a gateway whose
// child died keeps denying, it does not forward.
func (s *Server) Teardown() (removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.added {
		if e := s.B.RemovePeer(k); e != nil {
			err = errors.Join(err, e)
			continue
		}
		delete(s.added, k)
		removed++
	}
	return removed, err
}

package privsep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CallTimeout bounds one request: a parent that does not answer is a gateway
// that cannot be managed, and the child's caller should know.
const CallTimeout = 2 * time.Minute

// ErrClosed is returned by calls on a client whose session ended.
var ErrClosed = errors.New("privsep: the session with the privileged parent is closed")

// RefusedError is the parent's refusal of a request.
type RefusedError struct{ Msg string }

func (e *RefusedError) Error() string { return "privileged parent refused: " + e.Msg }

// FailedError is an operation the parent tried and the kernel refused.
type FailedError struct{ Msg string }

func (e *FailedError) Error() string { return "privileged parent: " + e.Msg }

type deadliner interface{ SetDeadline(time.Time) error }

// Client is the child's half. It is a wg.Gateway (peers) and a
// fw.TenantApplier (firewall), so the rest of the server does not know that
// the kernel is on the other side of a socket.
type Client struct {
	mu     sync.Mutex
	rw     io.ReadWriteCloser
	closed bool
	done   chan struct{}
	once   sync.Once
}

// NewClient is a Client over rw (a *net.UnixConn in the real child).
func NewClient(rw io.ReadWriteCloser) *Client {
	return &Client{rw: rw, done: make(chan struct{})}
}

// Done is closed when the session ends, by Close or by a failed call. The
// child has no gateway to manage after that.
func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) call(req Request) ([]byte, error) {
	body, err := req.encode()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClosed
	}
	if d, ok := c.rw.(deadliner); ok {
		_ = d.SetDeadline(time.Now().Add(CallTimeout))
	}
	if err := WriteFrame(c.rw, req.Type(), body); err != nil {
		c.endLocked()
		return nil, fmt.Errorf("privsep: %s: %w", req.Type(), err)
	}
	t, reply, err := ReadFrame(c.rw)
	if err != nil {
		c.endLocked()
		return nil, fmt.Errorf("privsep: %s: %w", req.Type(), err)
	}
	if t != req.Type()|ReplyFlag || len(reply) < 1 {
		c.endLocked()
		return nil, fmt.Errorf("privsep: %s: unexpected reply of type %d", req.Type(), uint8(t))
	}
	switch reply[0] {
	case StatusOK:
		return reply[1:], nil
	case StatusRefused:
		return nil, &RefusedError{Msg: string(reply[1:])}
	case StatusFailed:
		return nil, &FailedError{Msg: string(reply[1:])}
	}
	c.endLocked()
	return nil, fmt.Errorf("privsep: %s: reply status %d", req.Type(), reply[0])
}

func (c *Client) endLocked() {
	c.closed = true
	c.once.Do(func() { close(c.done) })
	_ = c.rw.Close()
}

// Close ends the session; the parent sees the end of the stream.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.endLocked()
	}
	return nil
}

// AddPeer implements wg.Gateway.
func (c *Client) AddPeer(pub wgtypes.Key, ip net.IP) error {
	a, ok := netip.AddrFromSlice(ip.To4())
	if !ok {
		return fmt.Errorf("add peer: %v is not an IPv4 address", ip)
	}
	_, err := c.call(AddPeer{Key: pub, IP: a})
	return err
}

// RemovePeer implements wg.Gateway.
func (c *Client) RemovePeer(pub wgtypes.Key) error {
	_, err := c.call(RemovePeer{Key: pub})
	return err
}

// Sweep asks the parent to remove the peers a previous run left, and returns
// how many it removed.
func (c *Client) Sweep() (int, error) {
	b, err := c.call(Sweep{})
	if err != nil {
		return 0, err
	}
	if len(b) != 4 {
		return 0, errors.New("privsep: sweep: malformed reply")
	}
	return int(binary.BigEndian.Uint32(b)), nil
}

// SetTunnelMTU asks the parent to set the tunnel MTU (0: derive it from the
// uplink) and returns the MTU in force.
func (c *Client) SetTunnelMTU(mtu int) (int, error) {
	if mtu < 0 || int64(mtu) > int64(^uint32(0)) {
		return 0, fmt.Errorf("set tunnel MTU: %d out of range", mtu)
	}
	b, err := c.call(SetMTU{MTU: uint32(mtu)})
	if err != nil {
		return 0, err
	}
	if len(b) != 4 {
		return 0, errors.New("privsep: set-mtu: malformed reply")
	}
	return int(binary.BigEndian.Uint32(b)), nil
}

// Apply satisfies fw.Applier and always fails: the child never builds a
// ruleset to hand over (the parent would not take one). A fw.Manager whose
// applier is a Client calls ApplyTenants instead.
func (c *Client) Apply(fw.Ruleset) error {
	return errors.New("privsep: a ruleset is built by the privileged parent from the tenants; use ApplyTenants")
}

// ApplyTenants implements fw.TenantApplier.
func (c *Client) ApplyTenants(ts []fw.Tenant) error {
	// The IDs do not cross the boundary: the order does, and it is Build's.
	sorted := append([]fw.Tenant(nil), ts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	_, err := c.call(Apply{Tenants: sorted})
	return err
}

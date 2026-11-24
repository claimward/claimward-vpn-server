//go:build openbsd

package pf

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/claimward/claimward-vpn-server/internal/fw"
)

// Applier loads a fw.Ruleset into pf through /dev/pf ioctls: no pfctl, no
// pf.conf written by the server. The administrator owns pf.conf and must call
// the anchor (`anchor "claimward"`); the Applier verifies that, loads the
// anchor in one transaction, and reads it back from the kernel before it
// returns nil.
type Applier struct {
	mu  sync.Mutex
	gen uint32

	// sysctl and open are the seams the tests use; NewApplier fills them.
	sysctl func(name string) (string, error)
	open   func() (int, error)
}

// NewApplier is the pf Applier. Its table generation starts from the clock so
// that two server runs never reuse a name that a crashed one left behind.
func NewApplier() *Applier {
	return &Applier{
		gen:    uint32(time.Now().Unix()),
		sysctl: unix.Sysctl,
		open:   func() (int, error) { return unix.Open(devPF, unix.O_RDWR, 0) },
	}
}

var _ fw.Applier = (*Applier)(nil)

// Apply verifies the host, loads rs and verifies the load. When the load
// succeeded but the read-back disagrees, the anchor is replaced with a
// deny-everything ruleset and an error is returned: a half-trusted ruleset is
// never left in force.
func (a *Applier) Apply(rs fw.Ruleset) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	rel, err := a.sysctl("kern.osrelease")
	if err != nil {
		return fmt.Errorf("pf: kern.osrelease: %w", err)
	}
	if err := CheckRelease(rel); err != nil {
		return err
	}
	a.gen++
	plan, err := NewPlan(rs, a.gen)
	if err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if len(plan.Rules) == 0 {
		return errors.New("pf: the ruleset has no rule")
	}
	iface := plan.Rules[0].Iface

	fd, err := a.open()
	if err != nil {
		return fmt.Errorf("pf: open %s: %w", devPF, err)
	}
	defer unix.Close(fd)

	if err := verifyHost(fd, iface); err != nil {
		return err
	}
	if err := loadWithRetry(fd, plan); err != nil {
		return err
	}
	if err := verifyLoaded(fd, plan); err != nil {
		if deny, derr := BlockAll(iface); derr == nil {
			if lerr := loadWithRetry(fd, deny); lerr != nil {
				err = fmt.Errorf("%w (and the deny-all fallback failed: %v)", err, lerr)
			}
		}
		return err
	}
	return nil
}

// verifyHost refuses to load unless pf is on, the main ruleset calls the
// anchor, and the interface is not skipped.
func verifyHost(fd int, iface string) error {
	on, err := pfRunning(fd)
	if err != nil {
		return err
	}
	if !on {
		return errors.New("pf: pf is disabled (enable it with `pfctl -e` or pf=YES in rc.conf.local)")
	}
	if err := verifyAnchorCalled(fd, iface); err != nil {
		return err
	}
	flags, known, err := ifaceFlags(fd, iface)
	if err != nil {
		return err
	}
	if known && flags&PFI_IFLAG_SKIP != 0 {
		return fmt.Errorf("pf: `set skip on` applies to %s: pf does not filter it, so the gateway's rules would not run; remove it from pf.conf", iface)
	}
	return nil
}

// verifyAnchorCalled requires an unrestricted `anchor "claimward"` rule in the
// main ruleset: any interface restriction, protocol, address or direction on
// it could hide a part of the traffic from the server's rules.
func verifyAnchorCalled(fd int, iface string) error {
	raw, err := readRules(fd, "")
	if err != nil {
		return err
	}
	for _, b := range raw {
		d, err := decodeRule(b)
		if err != nil || d.AnchorCall != AnchorName {
			continue // another rule, or one decodeRule does not model
		}
		if (d.Iface == "" || d.Iface == iface) && d.AF == 0 && d.Proto == 0 &&
			!d.Dst.IsValid() && d.SrcTable == "" && d.PortLo == 0 && d.Direction == 0 && !d.SynOnly {
			return nil
		}
	}
	return fmt.Errorf("pf: the main ruleset has no unrestricted `anchor %q` rule: add it to /etc/pf.conf and reload (the server never edits pf.conf)", AnchorName)
}

func loadWithRetry(fd int, p Plan) error {
	var err error
	for i, wait := 0, 50*time.Millisecond; i < 4; i, wait = i+1, wait*2 {
		if err = load(fd, p); !errors.Is(err, unix.EBUSY) {
			return err
		}
		time.Sleep(wait)
	}
	return err
}

// abiError names an ENODEV from the kernel: it is how pf says that the size of
// a structure we passed is not the size it has.
func abiError(op string, err error) error {
	if errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("pf: %s: the kernel's structure size differs from the one this build was generated for (ABI mismatch): %w", op, err)
	}
	return fmt.Errorf("pf: %s: %w", op, err)
}

// load replaces the tables and rules of the anchor in one transaction.
func load(fd int, p Plan) (err error) {
	ents := [2]PfiocTransE{{Type: PF_TRANS_TABLE}, {Type: PF_TRANS_RULESET}}
	for i := range ents {
		if err := setCString(ents[i].Anchor[:], AnchorName); err != nil {
			return err
		}
	}
	tr := PfiocTrans{Size: int32(len(ents)), Esize: SizeofPfiocTransE, Array: &ents[0]}
	if err := ioctl(fd, DIOCXBEGIN, unsafe.Pointer(&tr)); err != nil {
		return abiError("DIOCXBEGIN", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = ioctl(fd, DIOCXROLLBACK, unsafe.Pointer(&tr))
		}
	}()

	for _, t := range p.referencedTables() {
		addrs := make([]PfrAddr, 0, len(t.Addrs)+1)
		for _, a := range t.Addrs {
			e, err := addrOf(a)
			if err != nil {
				return err
			}
			addrs = append(addrs, e)
		}
		io := PfiocTable{
			Esize:  SizeofPfrAddr,
			Size:   int32(len(addrs)),
			Flags:  PFR_FLAG_ADDRSTOO,
			Ticket: ents[0].Ticket,
		}
		if len(addrs) > 0 {
			io.Buffer = (*byte)(unsafe.Pointer(&addrs[0]))
		}
		if err := setCString(io.Table.Anchor[:], AnchorName); err != nil {
			return err
		}
		if err := setCString(io.Table.Name[:], t.Name); err != nil {
			return err
		}
		if err := ioctl(fd, DIOCRINADEFINE, unsafe.Pointer(&io)); err != nil {
			return abiError("DIOCRINADEFINE "+t.Name, err)
		}
		// pfrio_nadd of DIOCRINADEFINE counts TABLES created (measured on 7.9: 1
		// for a table of two addresses), not addresses; the members are verified
		// by verifyLoaded, which reads every table back.
		if io.Nadd != 1 {
			return fmt.Errorf("pf: table %s: the kernel created %d tables, want 1", t.Name, io.Nadd)
		}
	}
	for i, s := range p.Rules {
		b, err := encodeRule(s, AnchorName, ents[1].Ticket, nil)
		if err != nil {
			return fmt.Errorf("pf: rule %d: %w", i, err)
		}
		if err := ioctl(fd, DIOCADDRULE, unsafe.Pointer(&b[0])); err != nil {
			return abiError(fmt.Sprintf("DIOCADDRULE #%d", i), err)
		}
	}
	if err := ioctl(fd, DIOCXCOMMIT, unsafe.Pointer(&tr)); err != nil {
		return abiError("DIOCXCOMMIT", err)
	}
	committed = true
	return nil
}

// verifyLoaded reads the anchor back from the kernel and compares it with p.
// The kernel's bytes are decoded by decodeRule, which shares nothing with the
// encoder, so a field the encoder wrote wrongly is a mismatch here and does not
// cancel itself out.
func verifyLoaded(fd int, p Plan) error {
	raw, err := readRules(fd, AnchorName)
	if err != nil {
		return err
	}
	if len(raw) != len(p.Rules) {
		return fmt.Errorf("pf: read-back: the anchor holds %d rules, loaded %d", len(raw), len(p.Rules))
	}
	for i, b := range raw {
		d, err := decodeRule(b)
		if err != nil {
			return fmt.Errorf("pf: read-back of rule %d: %w", i, err)
		}
		if err := checkRule(d, p.Rules[i]); err != nil {
			return fmt.Errorf("pf: read-back of rule %d: %w", i, err)
		}
	}
	for _, t := range p.referencedTables() {
		got, err := readTable(fd, AnchorName, t.Name, len(t.Addrs))
		if err != nil {
			return err
		}
		if err := checkTable(got, t); err != nil {
			return err
		}
	}
	return nil
}

// checkRule compares one decoded kernel rule with the Spec it must stand for.
func checkRule(d decodedRule, want Spec) error {
	if want.Dst.IsValid() && want.Dst.Bits() == 0 {
		// 0.0.0.0/0 and "any destination" are one pf address (all-zero
		// address and mask): the kernel cannot tell them apart.
		want.Dst = netip.Prefix{}
	}
	if d.Spec != want {
		return fmt.Errorf("kernel has %+v, want %+v", d.Spec, want)
	}
	if d.Direction != PF_IN {
		return fmt.Errorf("direction %d, want in", d.Direction)
	}
	if d.AnchorCall != "" {
		return fmt.Errorf("anchor call %q", d.AnchorCall)
	}
	if d.KeepState != keepStateFor(want.Action) {
		return fmt.Errorf("keep_state %d, want %d", d.KeepState, keepStateFor(want.Action))
	}
	if d.ScrubFlags != 0 { // max-mss is carried by max_mss alone, as pfctl writes it
		return fmt.Errorf("scrub_flags %#x, want 0", d.ScrubFlags)
	}
	return nil
}

// checkTable compares the addresses the kernel holds in a table with t's.
func checkTable(got []PfrAddr, t Table) error {
	if len(got) != len(t.Addrs) {
		return fmt.Errorf("pf: read-back: table %s holds %d addresses, loaded %d", t.Name, len(got), len(t.Addrs))
	}
	have := make([]netip.Addr, 0, len(got))
	for _, e := range got {
		if e.Af != unix.AF_INET || e.Net != 32 || e.Not != 0 {
			return fmt.Errorf("pf: read-back: table %s holds an entry that is not a plain IPv4 host (af %d net %d not %d)", t.Name, e.Af, e.Net, e.Not)
		}
		a, _ := netip.AddrFromSlice(e.U[:4])
		have = append(have, a)
	}
	want := append([]netip.Addr(nil), t.Addrs...)
	sort.Slice(have, func(i, j int) bool { return have[i].Less(have[j]) })
	sort.Slice(want, func(i, j int) bool { return want[i].Less(want[j]) })
	for i := range want {
		if have[i] != want[i] {
			return fmt.Errorf("pf: read-back: table %s differs at %d: kernel %s, loaded %s", t.Name, i, have[i], want[i])
		}
	}
	return nil
}

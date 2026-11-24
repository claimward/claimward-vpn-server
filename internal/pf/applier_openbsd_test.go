//go:build openbsd

package pf

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fw"
)

// The tests below run in the CI's OpenBSD VM, as root, against the real pf
// (CW_REQUIRE_OPENBSD=1). pfctl is used here ONLY as an observer and to set the
// administrator's pf.conf; the code under test never runs it.

func pfctl(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("pfctl", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("pfctl %v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

// flushAnchor empties an anchor; pfctl fails on one that does not exist yet,
// which is the state to reach, so the error is ignored.
func flushAnchor(name string) {
	_ = exec.Command("pfctl", "-a", name, "-F", "all").Run()
}

// pfHost is a root session with pf on, or a skip; main is the main ruleset it
// leaves in force, and the original is restored at the end.
func pfHost(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("pfctl")
	requireVM(t, "no pfctl in PATH", err == nil)
	requireVM(t, "not root", os.Geteuid() == 0)
	if _, err := os.Stat(devPF); err != nil {
		requireVM(t, devPF+" is absent", false)
	}
	_ = exec.Command("pfctl", "-e").Run() // "already enabled" is an error we do not care about
	if out, err := exec.Command("pfctl", "-si").CombinedOutput(); err != nil || !strings.Contains(string(out), "Status: Enabled") {
		t.Fatalf("pf is not enabled: %v\n%s", err, out)
	}
}

func setMain(t *testing.T, conf string) {
	t.Helper()
	pfctl(t, conf, "-f", "-")
	t.Cleanup(func() {
		pfctl(t, "anchor \"claimward\"\npass\n", "-f", "-")
		flushAnchor(AnchorName)
	})
}

func ensureIface(t *testing.T, name string) {
	t.Helper()
	if exec.Command("ifconfig", name).Run() == nil {
		return
	}
	if out, err := exec.Command("ifconfig", name, "create").CombinedOutput(); err != nil {
		requireVM(t, "cannot create "+name+": "+string(out), false)
	}
	t.Cleanup(func() { _ = exec.Command("ifconfig", name, "destroy").Run() })
}

func TestApplyLoadsAndReadsBack(t *testing.T) {
	pfHost(t)
	ensureIface(t, "wg0")
	setMain(t, "anchor \"claimward\"\npass\n")

	a := NewApplier()
	if err := a.Apply(sampleRuleset(t, 1390)); err != nil {
		t.Fatal(err)
	}
	rules := pfctl(t, "", "-a", AnchorName, "-sr")
	for _, want := range []string{
		"block drop in quick on wg0 all",
		"max-mss 1350",
		"max-mss 1330",
		"pass in quick on wg0 inet proto tcp from <t0_src_g",
		"to 192.168.1.0/24 port = 443 flags S/SA",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("pfctl -sr lacks %q:\n%s", want, rules)
		}
	}
	tables := pfctl(t, "", "-a", AnchorName, "-sT")
	if !strings.Contains(tables, "t0_src_g") || !strings.Contains(tables, "t1_src_g") {
		t.Errorf("pfctl -sT:\n%s", tables)
	}
}

func TestApplyReplacesThePreviousLoad(t *testing.T) {
	pfHost(t)
	ensureIface(t, "wg0")
	setMain(t, "anchor \"claimward\"\npass\n")

	a := NewApplier()
	if err := a.Apply(sampleRuleset(t, 1390)); err != nil {
		t.Fatal(err)
	}
	first := pfctl(t, "", "-a", AnchorName, "-sT")
	if err := a.Apply(fw.Build("wg0", []fw.Tenant{{ID: "only", Peers: []netip.Addr{netip.MustParseAddr("10.0.0.9")}}})); err != nil {
		t.Fatal(err)
	}
	// The second ruleset names no table: pf keeps none, and says so by exit
	// status or an empty list.
	secondOut, _ := exec.Command("pfctl", "-a", AnchorName, "-sT").CombinedOutput()
	second := string(secondOut)
	if first == second {
		t.Fatalf("the table generation did not change:\n%s", second)
	}
	if strings.Contains(second, "t1_src_g") {
		t.Errorf("a table of the first load survived:\n%s", second)
	}
	rulesOut, _ := exec.Command("pfctl", "-a", AnchorName, "-sr").CombinedOutput()
	rules := string(rulesOut)
	if strings.Contains(rules, "192.168.1.0/24") {
		t.Errorf("a rule of the first load survived:\n%s", rules)
	}
}

func TestApplyRefusesWhenTheMainRulesetDoesNotCallTheAnchor(t *testing.T) {
	pfHost(t)
	ensureIface(t, "wg0")
	flushAnchor(AnchorName)
	for name, conf := range map[string]string{
		"absent":     "pass\n",
		"other name": "anchor \"other\"\npass\n",
		"restricted": "anchor \"claimward\" proto tcp\npass\n",
		"to a host":  "anchor \"claimward\" to 192.0.2.1\npass\n",
		"inbound":    "anchor \"claimward\" in\npass\n",
	} {
		t.Run(name, func(t *testing.T) {
			setMain(t, conf)
			err := NewApplier().Apply(sampleRuleset(t, 0))
			if err == nil || !strings.Contains(err.Error(), "anchor") {
				t.Fatalf("Apply = %v", err)
			}
			// An anchor never created is the expected state after a refusal: pfctl
			// then says "Anchor does not exist" (and exits 0).
			out, _ := exec.Command("pfctl", "-a", AnchorName, "-sr").CombinedOutput()
			if rules := strings.TrimSpace(string(out)); rules != "" && !strings.Contains(rules, "Anchor does not exist") {
				t.Errorf("a refused Apply loaded rules:\n%s", rules)
			}
		})
	}
}

func TestApplyRefusesSetSkipOnTheInterface(t *testing.T) {
	pfHost(t)
	ensureIface(t, "wg0")
	flushAnchor(AnchorName)
	for name, conf := range map[string]string{
		"interface": "set skip on wg0\nanchor \"claimward\"\npass\n",
		"group":     "set skip on wg\nanchor \"claimward\"\npass\n",
	} {
		t.Run(name, func(t *testing.T) {
			setMain(t, conf)
			err := NewApplier().Apply(sampleRuleset(t, 0))
			if err == nil || !strings.Contains(err.Error(), "set skip") {
				t.Fatalf("Apply = %v", err)
			}
		})
	}
}

func TestApplyRefusesAnUnsupportedRelease(t *testing.T) {
	a := &Applier{
		sysctl: func(string) (string, error) { return "7.8", nil },
		open: func() (int, error) {
			t.Fatal("/dev/pf was opened on an unsupported release")
			return -1, nil
		},
	}
	if err := a.Apply(sampleRuleset(t, 0)); err == nil || !strings.Contains(err.Error(), "7.8") {
		t.Fatalf("Apply = %v", err)
	}
}

func TestApplyRefusesWhenSysctlFails(t *testing.T) {
	boom := errors.New("boom")
	a := &Applier{sysctl: func(string) (string, error) { return "", boom }}
	if err := a.Apply(sampleRuleset(t, 0)); !errors.Is(err, boom) {
		t.Fatalf("Apply = %v", err)
	}
}

// The comparison between what was loaded and what the kernel reports must
// notice every field of a rule.
func TestCheckRuleNoticesEachField(t *testing.T) {
	base := Spec{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: protoTCP, SrcTable: "t", Dst: netip.MustParsePrefix("10.0.0.0/8"), PortLo: 1, PortHi: 2, SynOnly: true}
	good := decodedRule{Spec: base, Direction: PF_IN, KeepState: PF_STATE_NORMAL}
	if err := checkRule(good, base); err != nil {
		t.Fatalf("an exact match was refused: %v", err)
	}
	mut := map[string]func(*decodedRule){
		"action":      func(d *decodedRule) { d.Action = Block },
		"quick":       func(d *decodedRule) { d.Quick = false },
		"iface":       func(d *decodedRule) { d.Iface = "wg1" },
		"af":          func(d *decodedRule) { d.AF = 0 },
		"proto":       func(d *decodedRule) { d.Proto = protoUDP },
		"table":       func(d *decodedRule) { d.SrcTable = "u" },
		"dst":         func(d *decodedRule) { d.Dst = netip.MustParsePrefix("10.0.0.0/9") },
		"port lo":     func(d *decodedRule) { d.PortLo = 2 },
		"port hi":     func(d *decodedRule) { d.PortHi = 3 },
		"syn":         func(d *decodedRule) { d.SynOnly = false },
		"direction":   func(d *decodedRule) { d.Direction = 0 },
		"keep state":  func(d *decodedRule) { d.KeepState = 0 },
		"anchor call": func(d *decodedRule) { d.AnchorCall = "x" },
		"scrub":       func(d *decodedRule) { d.ScrubFlags = PFSTATE_SCRUB_TCP },
		"mss":         func(d *decodedRule) { d.MaxMSS = 1200 },
	}
	for name, f := range mut {
		d := good
		f(&d)
		if checkRule(d, base) == nil {
			t.Errorf("a rule that differs in %s was accepted", name)
		}
	}
	any := Spec{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Dst: netip.MustParsePrefix("0.0.0.0/0")}
	if err := checkRule(decodedRule{Spec: Spec{Action: Pass, Quick: true, Iface: "wg0", AF: 4}, Direction: PF_IN, KeepState: PF_STATE_NORMAL}, any); err != nil {
		t.Errorf("0.0.0.0/0 against the kernel's any: %v", err)
	}
	mss := Spec{Action: Match, Iface: "wg0", AF: 4, Proto: protoTCP, MaxMSS: 1300}
	if err := checkRule(decodedRule{Spec: mss, Direction: PF_IN}, mss); err == nil {
		t.Error("a max-mss rule without the scrub flag was accepted")
	}
	if err := checkRule(decodedRule{Spec: mss, Direction: PF_IN, ScrubFlags: PFSTATE_SCRUB_TCP}, mss); err != nil {
		t.Errorf("a correct max-mss rule: %v", err)
	}
}

func TestCheckTable(t *testing.T) {
	a1, a2 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	e1, _ := addrOf(a1)
	e2, _ := addrOf(a2)
	tab := Table{Name: "t", Addrs: []netip.Addr{a2, a1}}
	if err := checkTable([]PfrAddr{e1, e2}, tab); err != nil {
		t.Fatalf("same set, other order: %v", err)
	}
	if checkTable([]PfrAddr{e1}, tab) == nil {
		t.Error("a missing address was accepted")
	}
	if checkTable([]PfrAddr{e1, e1}, tab) == nil {
		t.Error("a duplicated address was accepted")
	}
	bad := e2
	bad.Net = 24
	if checkTable([]PfrAddr{e1, bad}, tab) == nil {
		t.Error("a /24 entry was accepted")
	}
	bad = e2
	bad.Not = 1
	if checkTable([]PfrAddr{e1, bad}, tab) == nil {
		t.Error("a negated entry was accepted")
	}
}

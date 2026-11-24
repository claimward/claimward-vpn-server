//go:build openbsd

package pf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// requireVM reports whether this is the CI's OpenBSD VM; elsewhere the test
// skips, in the VM (CW_REQUIRE_OPENBSD=1) a missing prerequisite is a failure.
func requireVM(t *testing.T, what string, ok bool) {
	t.Helper()
	if ok {
		return
	}
	if os.Getenv("CW_REQUIRE_OPENBSD") == "1" {
		t.Fatalf("CW_REQUIRE_OPENBSD=1 but %s", what)
	}
	t.Skip(what)
}

const cPreamble = `#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/pfvar.h>
#include <stddef.h>
#include <stdio.h>
`

// cProgram prints "<struct> <field> <offsetof> <sizeof member>" for every
// member and "sizeof <struct> <n>" for every structure.
func cProgram(ms []member, structs []string) string {
	var b strings.Builder
	b.WriteString(cPreamble)
	b.WriteString("int main(void) {\n")
	for _, m := range ms {
		fmt.Fprintf(&b, "printf(\"%s %s %%zu %%zu\\n\", offsetof(struct %s, %s), sizeof(((struct %s *)0)->%s));\n",
			m.Struct, m.Field, m.Struct, m.Field, m.Struct, m.Field)
	}
	for _, s := range structs {
		fmt.Fprintf(&b, "printf(\"sizeof %s %%zu\\n\", sizeof(struct %s));\n", s, s)
	}
	b.WriteString("return 0;\n}\n")
	return b.String()
}

// TestLayoutAgainstC compiles a C program against THIS release's <net/pfvar.h>
// and compares the offset and the size of EVERY member the package reads or
// writes, and the size of every structure it passes to the kernel, with the
// Go side. The generated ztypes file is what the pfabi lane diffed; this is
// what proves that the table in layout_openbsd.go (including the sizes written
// by hand) says what the kernel's header says.
func TestLayoutAgainstC(t *testing.T) {
	cc, err := exec.LookPath("cc")
	requireVM(t, "no C compiler (cc) in PATH", err == nil)

	structSizes := map[string]uintptr{
		"pf_rule":       SizeofPfRule,
		"pfioc_rule":    SizeofPfiocRule,
		"pfioc_table":   SizeofPfiocTable,
		"pfr_table":     SizeofPfrTable,
		"pfr_addr":      SizeofPfrAddr,
		"pfioc_trans":   SizeofPfiocTrans,
		"pfioc_trans_e": SizeofPfiocTransE,
		"pf_status":     SizeofPfStatus,
		"pf_rule_addr":  SizeofPfRuleAddr,
		"pf_addr_wrap":  SizeofPfAddrWrap,
		"pf_addr":       SizeofPfAddr,
		"pfi_kif":       SizeofPfiKif,
		"pfioc_iface":   unsafe.Sizeof(PfiocIface{}),
	}
	var names []string
	for n := range structSizes {
		names = append(names, n)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "layout.c")
	if err := os.WriteFile(src, []byte(cProgram(allMembers, names)), 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "layout")
	if out, err := exec.Command(cc, "-o", exe, src).CombinedOutput(); err != nil {
		t.Fatalf("cc: %v\n%s", err, out)
	}
	out, err := exec.Command(exe).Output()
	if err != nil {
		t.Fatal(err)
	}

	type key struct{ s, f string }
	type val struct{ off, size int }
	got := map[key]val{}
	sizes := map[string]uintptr{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 3 && f[0] == "sizeof":
			n, _ := strconv.Atoi(f[2])
			sizes[f[1]] = uintptr(n)
		case len(f) == 4:
			o, _ := strconv.Atoi(f[2])
			s, _ := strconv.Atoi(f[3])
			got[key{f[0], f[1]}] = val{o, s}
		default:
			t.Fatalf("unexpected line %q", line)
		}
	}
	if len(got) != len(allMembers) {
		t.Fatalf("C printed %d members, the table has %d (duplicate entry?)", len(got), len(allMembers))
	}
	for _, m := range allMembers {
		c, ok := got[key{m.Struct, m.Field}]
		if !ok {
			t.Errorf("%s.%s: C printed nothing", m.Struct, m.Field)
			continue
		}
		if c.off != m.Off || c.size != m.Size {
			t.Errorf("%s.%s: Go says offset %#x size %d, C says offset %#x size %d",
				m.Struct, m.Field, m.Off, m.Size, c.off, c.size)
		}
	}
	for n, want := range structSizes {
		if sizes[n] != want {
			t.Errorf("sizeof(struct %s): Go %d, C %d", n, want, sizes[n])
		}
	}
	// The Go struct a ioctl receives by pointer must have the C size too.
	for n, g := range map[string]uintptr{
		"pfr_addr":      unsafe.Sizeof(PfrAddr{}),
		"pfr_table":     unsafe.Sizeof(PfrTable{}),
		"pfioc_table":   unsafe.Sizeof(PfiocTable{}),
		"pfioc_trans":   unsafe.Sizeof(PfiocTrans{}),
		"pfioc_trans_e": unsafe.Sizeof(PfiocTransE{}),
		"pf_status":     unsafe.Sizeof(PfStatus{}),
		"pf_rule_addr":  unsafe.Sizeof(PfRuleAddr{}),
		"pf_addr_wrap":  unsafe.Sizeof(PfAddrWrap{}),
	} {
		if g != sizes[n] {
			t.Errorf("unsafe.Sizeof of the Go type for struct %s is %d, C says %d", n, g, sizes[n])
		}
	}
}

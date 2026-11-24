package rcproof

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	dayLog     = "/var/log/daemon"
	listening  = "claimward-server listening"
	noAnchor   = "has no unrestricted `anchor"
	pfConfGood = "set skip on lo\nanchor \"claimward\"\n"
	pfConfNone = "set skip on lo\n"
)

// requireVM: elsewhere the test skips; in the CI's VM (CW_REQUIRE_OPENBSD=1) a
// missing prerequisite is a failure.
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

func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func must(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := run(t, name, args...)
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func logSize(t *testing.T) int64 {
	t.Helper()
	fi, err := os.Stat(dayLog)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// logSince is what syslogd wrote to the daemon log after offset.
func logSince(t *testing.T, offset int64) string {
	t.Helper()
	b, err := os.ReadFile(dayLog)
	if err != nil || int64(len(b)) < offset {
		t.Fatalf("read %s: %v", dayLog, err)
	}
	return string(b[offset:])
}

// waitLog polls the log after offset until it holds want, or fails.
func waitLog(t *testing.T, offset int64, want string) string {
	t.Helper()
	var got string
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		if got = logSince(t, offset); strings.Contains(got, want) {
			return got
		}
	}
	t.Fatalf("%q never reached %s; it holds:\n%s", want, dayLog, got)
	return ""
}

func TestRcdScriptStartsChecksStopsAndRefusesWithoutTheAnchor(t *testing.T) {
	bin := os.Getenv("CW_SERVER_BIN")
	deploy := os.Getenv("CW_DEPLOY_DIR")
	_, rcctl := exec.LookPath("rcctl")
	requireVM(t, "not the CI VM (needs rcctl, CW_SERVER_BIN, CW_DEPLOY_DIR)", rcctl == nil && bin != "" && deploy != "" && os.Getuid() == 0)

	rel := strings.TrimSpace(must(t, "sysctl", "-n", "kern.osrelease"))
	t.Logf("OpenBSD %s", rel)

	// The server is installed, the same way the README says.
	must(t, "install", "-m", "0555", bin, "/usr/local/bin/claimward-server")
	must(t, "install", "-m", "0555", filepath.Join(deploy, "claimward_server"), "/etc/rc.d/claimward_server")
	must(t, "install", "-d", "-m", "0755", "-o", "root", "-g", "wheel", "/etc/claimward")
	must(t, "install", "-d", "-m", "0700", "-o", "root", "-g", "wheel", "/etc/claimward/credentials")

	// Secrets: root-owned, 0400, created from stdin-free files so no value is
	// ever in an argument list.
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(rawKey)
	tmp := t.TempDir()
	src := filepath.Join(tmp, "wg-private-key")
	if err := os.WriteFile(src, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, "install", "-m", "0400", "-o", "root", "-g", "wheel", src, "/etc/claimward/credentials/wg-private-key")

	// Non-secret settings (the shipped example, loopback listeners).
	env, err := os.ReadFile(filepath.Join(deploy, "environment.example"))
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(tmp, "environment")
	extra := "LISTEN_ADDR=127.0.0.1:8443\nGRPC_ADDR=127.0.0.1:8444\n"
	if err := os.WriteFile(envFile, append(env, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, "install", "-m", "0600", "-o", "root", "-g", "wheel", envFile, "/etc/claimward/environment")

	// wg0 from the shipped hostname.if(5) file, brought up by netstart(8).
	hn, err := os.ReadFile(filepath.Join(deploy, "hostname.wg0.example"))
	if err != nil {
		t.Fatal(err)
	}
	hnFile := filepath.Join(tmp, "hostname.wg0")
	if err := os.WriteFile(hnFile, []byte(strings.Replace(string(hn), "REPLACE_WITH_THE_BASE64_PRIVATE_KEY", key, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, "install", "-m", "0640", "-o", "root", "-g", "wheel", hnFile, "/etc/hostname.wg0")
	must(t, "sh", "/etc/netstart", "wg0")
	must(t, "ifconfig", "wg0")

	// pf on, the anchor called.
	pf := func(conf string) {
		t.Helper()
		f := filepath.Join(tmp, "pf.conf")
		if err := os.WriteFile(f, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		must(t, "install", "-m", "0600", "-o", "root", "-g", "wheel", f, "/etc/pf.conf")
		must(t, "pfctl", "-f", "/etc/pf.conf")
	}
	_, _ = run(t, "pfctl", "-e") // "already enabled" is not an error that matters
	t.Cleanup(func() {
		_, _ = run(t, "rcctl", "stop", "claimward_server")
		pf(pfConfGood)
		_, _ = run(t, "ifconfig", "wg0", "destroy")
		_ = os.Remove("/etc/hostname.wg0")
	})
	_, _ = run(t, "rcctl", "stop", "claimward_server")
	pf(pfConfGood)

	// 1. The start works, the startup line is logged, rcctl check passes.
	off := logSize(t)
	out, err := run(t, "rcctl", "start", "claimward_server")
	if err != nil {
		t.Fatalf("rcctl start: %v\n%s\nlog:\n%s", err, out, logSince(t, off))
	}
	waitLog(t, off, listening)
	if out, err := run(t, "rcctl", "check", "claimward_server"); err != nil {
		t.Fatalf("rcctl check after start: %v\n%s", err, out)
	}
	// The policy is in the anchor: the default deny on wg0 is loaded.
	if rules := must(t, "pfctl", "-a", "claimward", "-sr"); !strings.Contains(rules, "wg0") {
		t.Errorf("the anchor holds no rule for wg0:\n%s", rules)
	}
	if out, err := run(t, "rcctl", "stop", "claimward_server"); err != nil {
		t.Fatalf("rcctl stop: %v\n%s", err, out)
	}
	if out, err := run(t, "rcctl", "check", "claimward_server"); err == nil {
		t.Fatalf("rcctl check passes after stop:\n%s", out)
	}

	// 2. Negative control: with the anchor gone from pf.conf the start fails,
	// and the server says why.
	pf(pfConfNone)
	off = logSize(t)
	if out, err := run(t, "rcctl", "start", "claimward_server"); err == nil {
		t.Fatalf("rcctl start succeeded without the anchor:\n%s", out)
	}
	waitLog(t, off, noAnchor)
	if got := logSince(t, off); strings.Contains(got, listening) {
		t.Fatalf("the server reported listening without the anchor:\n%s", got)
	}
	if out, err := run(t, "rcctl", "check", "claimward_server"); err == nil {
		t.Fatalf("rcctl check passes without the anchor:\n%s", out)
	}
}

package rcproof

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/fakeauthn"
	"github.com/go-authn/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	childUser  = "_claimward"
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
	// The unprivileged account, as the README creates it.
	if _, err := run(t, "id", childUser); err != nil {
		must(t, "useradd", "-g", "=uid", "-c", "claimward", "-d", "/var/empty", "-s", "/sbin/nologin", "-r", "1..999", childUser)
	}
	must(t, "install", "-d", "-m", "0755", "-o", "root", "-g", "wheel", "/etc/claimward")
	must(t, "install", "-d", "-m", "0700", "-o", childUser, "-g", childUser, "/etc/claimward/credentials")

	// Secrets: owned by the unprivileged account, 0400, created from stdin-free
	// files so no value is ever in an argument list.
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
	keyCred := "/etc/claimward/credentials/wg-private-key"
	must(t, "install", "-m", "0400", "-o", childUser, "-g", childUser, src, keyCred)
	gwSecret := filepath.Join(tmp, "goauthn-gateway-secret")
	if err := os.WriteFile(gwSecret, []byte(fakeauthn.GatewaySecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, "install", "-m", "0400", "-o", childUser, "-g", childUser, gwSecret, "/etc/claimward/credentials/goauthn-gateway-secret")

	// A go-authn provider in this process, which knows one device and one
	// institution; the tenant names the institution.
	prov := fakeauthn.New(t)
	devPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	devPub := devPriv.PublicKey().String()
	pk, err := wireguard.ParseKey(devPub)
	if err != nil {
		t.Fatal(err)
	}
	prov.SetPeers(1, wireguard.Peer{Key: pk, Subject: "sub-alice", Expires: time.Now().Add(time.Hour)})
	tenants := filepath.Join(tmp, "tenants.json")
	if err := os.WriteFile(tenants, []byte(`[{"id":"default","idps":["https://idp.example/idp"],"policy":[{"cidr":"10.80.0.0/24","proto":"tcp","ports":[22]}]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, "install", "-m", "0400", "-o", childUser, "-g", childUser, tenants, "/etc/claimward/tenants.json")

	// Non-secret settings (the shipped example, loopback listeners, the provider).
	env, err := os.ReadFile(filepath.Join(deploy, "environment.example"))
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(tmp, "environment")
	extra := "LISTEN_ADDR=127.0.0.1:8443\nGRPC_ADDR=127.0.0.1:8444\n" +
		"AUTH_PROVIDER=go-authn\nOIDC_ISSUER=" + prov.Issuer() + "\nOIDC_CLIENT_ID=" + fakeauthn.Audience + "\n" +
		"GOAUTHN_GATEWAY_CLIENT_ID=" + fakeauthn.GatewayID + "\nTENANTS_FILE=/etc/claimward/tenants.json\n"
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

	// Privilege separation: the process that serves the network is the
	// unprivileged account's, the one that drives the kernel is root's, and
	// the secret is the account's alone.
	if got := strings.TrimSpace(must(t, "stat", "-f", "%Su %Mp%Lp", keyCred)); got != childUser+" 0400" {
		t.Errorf("the key credential is %q, want %q", got, childUser+" 0400")
	}
	// ps(1) cuts a user name to 8 characters, so the accounts are compared by uid.
	childUID := strings.TrimSpace(must(t, "id", "-u", childUser))
	var child, parent int
	for _, line := range strings.Split(must(t, "ps", "-ax", "-o", "uid,args"), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "/usr/local/bin/claimward-server" {
			continue // not the server (the shell that started it has a longer command line)
		}
		switch {
		case len(f) >= 3 && f[2] == "privsep-child":
			if f[0] != childUID {
				t.Errorf("the serving process runs as uid %q, want %s's %s: %s", f[0], childUser, childUID, line)
			}
			child++
		case len(f) == 2:
			if f[0] != "0" {
				t.Errorf("the privileged process runs as %q: %s", f[0], line)
			}
			parent++
		}
	}
	if child != 1 || parent != 1 {
		t.Errorf("want one privileged parent and one %s child, saw %d and %d\n%s", childUser, parent, child, must(t, "ps", "-ax", "-o", "user,args"))
	}
	if got := logSince(t, off); !strings.Contains(got, "restricted") {
		t.Errorf("the child never reported its unveil and pledge:\n%s", got)
	}

	// A device enrolls through the child; the peer lands on wg0 through the parent.
	enroll := func(key string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(protocol.EnrollRequest{PublicKey: key})
		req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8443"+protocol.PathEnroll, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+prov.AccessToken("sub-alice", "alice", map[string]any{"idp": "https://idp.example/idp"}))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// wgctrl's OpenBSD driver is read-only (ConfigureDevice returns a sentinel),
	// so the parent cannot program a peer on OpenBSD yet: this is not new with
	// privilege separation, and the enrolment is refused with a gateway error.
	// What this lane can prove is that the request left the pledged child, was
	// validated by the parent and reached its gateway.
	if code, _ := enroll(devPub); code == http.StatusOK {
		t.Errorf("enroll succeeded although wgctrl cannot configure wg0 on OpenBSD; update this test and the README")
	}
	if got := logSince(t, off); !strings.Contains(got, "privileged parent: add peer") {
		t.Errorf("the child's peer request never reached the parent:\n%s", got)
	}
	// Negative control: a key the provider never registered is refused by the
	// child, and does not reach wg0.
	other, _ := wgtypes.GeneratePrivateKey()
	if code, _ := enroll(other.PublicKey().String()); code == http.StatusOK {
		t.Errorf("an unregistered key enrolled")
	}
	if wgOut := must(t, "ifconfig", "wg0"); strings.Contains(wgOut, other.PublicKey().String()) {
		t.Errorf("an unregistered key reached wg0")
	}

	if out, err := run(t, "rcctl", "stop", "claimward_server"); err != nil {
		t.Fatalf("rcctl stop: %v\n%s", err, out)
	}
	if out, err := run(t, "rcctl", "check", "claimward_server"); err == nil {
		t.Fatalf("rcctl check passes after stop:\n%s", out)
	}

	// 1b. Negative control: a secret the unprivileged account does not own is
	// refused (rc_configtest does not look at the key file, the server does),
	// and the server does not come up.
	must(t, "chown", "root:wheel", keyCred)
	off = logSize(t)
	if out, err := run(t, "rcctl", "start", "claimward_server"); err == nil {
		_, _ = run(t, "rcctl", "stop", "claimward_server")
		t.Fatalf("rcctl start succeeded with a credential the unprivileged account does not own:\n%s", out)
	}
	time.Sleep(2 * time.Second)
	if got := logSince(t, off); strings.Contains(got, listening) {
		t.Fatalf("the server came up with a credential it does not own:\n%s", got)
	}
	must(t, "chown", childUser+":"+childUser, keyCred)

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

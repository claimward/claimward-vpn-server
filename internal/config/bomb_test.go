//go:build linux || darwin

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// The bomb tests: a hostile PROVIDERS_FILE or SERVER_LOGO_FILE must be REFUSED
// without being read whole. They run in a CHILD copy of the test binary under
// GOMEMLIMIT and RLIMIT_AS (the `ulimit -v` of a shell), never against the
// host's memory, and a limit set in the test process itself would bind every
// other test.
const (
	bombEnv     = "CLAIMWARD_BOMB_CHILD"
	bombGoMem   = "64MiB"
	bombAddrMiB = 2048           // RLIMIT_AS of the child, MiB
	bombSparse  = int64(4) << 30 // 4 GiB, a sparse file: no disk, no memory
	bombBudget  = 16 << 20       // bytes a refusal may allocate
)

// bombFiles writes the hostile inputs and returns name -> path.
func bombFiles(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	out := map[string]string{}
	sparse := func(name string) string {
		p := filepath.Join(dir, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := f.Truncate(bombSparse); err != nil {
			t.Skipf("no sparse files here: %v", err)
		}
		return p
	}
	out["providers-sparse"] = sparse("big.json")
	out["logo-sparse"] = sparse("big.svg")
	deep := filepath.Join(dir, "deep.json")
	if err := os.WriteFile(deep, []byte(`{"providers":`+strings.Repeat("[", maxProvidersFile/2)+strings.Repeat("]", maxProvidersFile/2)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out["providers-deep"] = deep
	return out
}

func TestBombsAreRefusedUnderAMemoryLimit(t *testing.T) {
	files := bombFiles(t)
	for name, path := range files {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBombChild$", "-test.v")
			cmd.Env = append(os.Environ(), bombEnv+"="+name+"="+path, "GOMEMLIMIT="+bombGoMem)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "BOMB-REFUSED "+name) {
				t.Fatalf("child did not refuse %s: %v\n%s", name, err, out)
			}
		})
	}
}

// TestBombChild runs only in the child: it is a no-op in a normal run.
func TestBombChild(t *testing.T) {
	spec := os.Getenv(bombEnv)
	if spec == "" {
		t.Skip("child only")
	}
	name, path, _ := strings.Cut(spec, "=")
	lim := &syscall.Rlimit{Cur: bombAddrMiB << 20, Max: bombAddrMiB << 20}
	// darwin does not enforce RLIMIT_AS (and may refuse to set it); there the
	// GOMEMLIMIT and the allocation budget are the bound, on linux all three.
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, lim); err != nil && runtime.GOOS != "darwin" {
		t.Fatalf("setrlimit AS: %v", err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var err error
	switch {
	case strings.HasPrefix(name, "providers"):
		_, err = loadProviders(path, t.TempDir())
	default:
		_, _, err = loadLogo(path)
	}
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatalf("%s was accepted", name)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > bombBudget {
		t.Fatalf("%s: the refusal allocated %d bytes, budget %d", name, grew, bombBudget)
	}
	t.Logf("BOMB-REFUSED %s: %v", name, err)
}

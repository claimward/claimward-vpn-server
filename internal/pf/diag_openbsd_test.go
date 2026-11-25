//go:build openbsd

package pf

import (
	"os/exec"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// DIAGNOSTIC (temporary): who turns pf off between two Apply calls.
func TestDiagPfStaysEnabled(t *testing.T) {
	pfHost(t)
	fd, err := unix.Open(devPF, unix.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var mu sync.Mutex
	var log []string
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		last := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			on, err := pfRunning(fd)
			if err == nil && on != last {
				out, _ := exec.Command("pfctl", "-si").CombinedOutput()
				mu.Lock()
				log = append(log, time.Now().Format("15:04:05.000000")+" running="+map[bool]string{true: "1", false: "0"}[on]+"\n"+string(out))
				mu.Unlock()
				last = on
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	for i := 0; i < 25; i++ {
		t.Run("mss", func(t *testing.T) { TestMSSClampActsOnTheWire(t) })
		mu.Lock()
		n := len(log)
		mu.Unlock()
		if n > 0 {
			break
		}
	}
	close(stop)
	<-done
	for _, l := range log {
		t.Logf("TRANSITION %s", l)
	}
	if len(log) > 0 {
		t.Fatalf("pf changed state %d times", len(log))
	}
}

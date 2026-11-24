//go:build openbsd

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/privsep"
	"github.com/claimward/claimward-vpn-server/internal/wg"
	"golang.org/x/sys/unix"
)

// childPromises is everything the serving process may do after start: read
// files (unveiled), talk on the network, resolve names. No exec, no proc, no
// wpath, no unix sockets, no ioctl, no route.
const childPromises = "stdio rpath inet dns"

// privsepMain starts the right half. handled is false when this run is a
// dry run, which stays a single process.
func privsepMain(log *slog.Logger) (handled bool, err error) {
	if len(os.Args) > 1 && os.Args[1] == childRole {
		return true, runChild(log)
	}
	g, err := config.LoadGateway()
	if err != nil {
		return true, err
	}
	if g.DryRun {
		return false, nil
	}
	return true, runParent(log, g)
}

// runChild is the unprivileged process: the whole server, with its kernel
// side delegated to the parent over descriptor 3.
func runChild(log *slog.Logger) error {
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	if err := requireUnprivileged(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups); err != nil {
		return err
	}
	conn, err := privsep.ParentConn()
	if err != nil {
		return err
	}
	return run(log, privsep.NewClient(conn))
}

// runParent is the privileged process. It reads no credential and serves no
// network: it opens the WireGuard device and pf, starts the child as
// _claimward, and answers the child's few kinds of request.
func runParent(log *slog.Logger, g config.Gateway) error {
	if os.Geteuid() != 0 {
		return errors.New("the privileged process must start as root (it drives WireGuard and pf); it hands everything else to " + childUser)
	}
	u, err := user.Lookup(childUser)
	if err != nil {
		return fmt.Errorf("the unprivileged account %s: %w (create it: see deploy/README.md)", childUser, err)
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil || uid == 0 || gid == 0 {
		return fmt.Errorf("the account %s has uid %q gid %q: it must not be root", childUser, u.Uid, u.Gid)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	gw, err := wg.NewGateway(g.Interface)
	if err != nil {
		return err
	}
	defer gw.Close()
	be := &privilegedBackend{gw: gw, ap: platformApplier(), iface: g.Interface, pool: g.Pool,
		uplink: wg.UplinkMTU, setMTU: wg.SetInterfaceMTU}
	srv := privsep.NewServer(be, privsep.Limits{Pool: g.Pool, MinMTU: config.MinTunnelMTU, MaxMTU: config.MaxTunnelMTU}, log)

	// The child gets the same environment (it holds no secret: those are files
	// under CREDENTIALS_DIRECTORY, readable only by _claimward) and no groups.
	ch, err := privsep.StartChild(exe, []string{childRole}, os.Environ(),
		&syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}})
	if err != nil {
		return err
	}
	log.Info("unprivileged process started", "pid", ch.Cmd.Process.Pid, "user", childUser)

	// After the fork, which needs no file: the parent may open /dev/pf and
	// nothing else.
	if err := unix.Unveil("/dev/pf", "rw"); err != nil {
		_ = ch.Cmd.Process.Kill()
		return fmt.Errorf("unveil /dev/pf: %w", err)
	}
	if err := unix.UnveilBlock(); err != nil {
		_ = ch.Cmd.Process.Kill()
		return fmt.Errorf("unveil: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = ch.Cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(15*time.Second, func() { _ = ch.Cmd.Process.Kill() })
	}()

	serveErr := srv.Serve(ch.Conn)
	// The session is over: whatever ended it, the child must not outlive it.
	_ = ch.Conn.Close()
	_ = ch.Cmd.Process.Kill()
	waitErr := ch.Cmd.Wait()
	if n, err := srv.Teardown(); err != nil {
		log.Error("removing the peers this run added", "removed", n, "err", err)
	} else if n > 0 {
		log.Info("removed the peers this run added", "peers", n)
	}
	if serveErr != nil {
		return serveErr
	}
	if ctx.Err() != nil {
		return nil // asked to stop; the child's exit is the answer
	}
	return fmt.Errorf("the unprivileged process ended: %v", waitErr)
}

// lockdown unveils the files that remain and pledges. ⛔ Any failure stops the
// server: a process that could not restrict itself serves nobody.
func lockdown(cfg *config.Config, log *slog.Logger) error {
	for _, p := range []string{cfg.TLSCert, cfg.TLSKey, cfg.TenantsFile} {
		if p == "" {
			continue
		}
		if err := unix.Unveil(p, "r"); err != nil {
			return fmt.Errorf("unveil %s: %w", p, err)
		}
	}
	// What Go's resolver, the clock and TLS roots read; a host without one of
	// them is not an error.
	for _, p := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/ssl", "/etc/localtime", "/etc/services"} {
		if err := unix.Unveil(p, "r"); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("unveil %s: %w", p, err)
		}
	}
	if err := unix.UnveilBlock(); err != nil {
		return fmt.Errorf("unveil: %w", err)
	}
	// Witness that the unveil took: a world-readable file nobody listed.
	if f, err := os.Open("/etc/passwd"); err == nil {
		f.Close()
		return errors.New("unveil did not restrict the file system: /etc/passwd is still readable")
	}
	// Exec promises stay empty, and exec is not among the promises.
	if err := unix.Pledge(childPromises, ""); err != nil {
		return fmt.Errorf("pledge %q: %w", childPromises, err)
	}
	log.Info("restricted", "pledge", childPromises)
	return nil
}

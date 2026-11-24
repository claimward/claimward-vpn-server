package main

import (
	"errors"
	"fmt"
)

// childRole is the hidden first argument of the unprivileged process. The
// parent starts it; nothing documents it as an interface.
const childRole = "privsep-child"

// childUser is the account the unprivileged process runs as. The deploy
// creates it; the parent refuses to start without it.
const childUser = "_claimward"

// requireUnprivileged refuses a child that still has any root identity: a
// child that cannot drop privileges is not started, and there is no opt-out.
func requireUnprivileged(uid, euid, gid, egid int, groups []int) error {
	if uid == 0 || euid == 0 || gid == 0 || egid == 0 {
		return fmt.Errorf("the unprivileged process runs with uid %d/%d gid %d/%d: refusing to serve as root", uid, euid, gid, egid)
	}
	for _, g := range groups {
		if g == 0 {
			return errors.New("the unprivileged process is in group 0: refusing to serve")
		}
	}
	return nil
}

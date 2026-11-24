package creds

import (
	"encoding/binary"
	"strings"
	"testing"
)

type ent struct {
	tag, perm uint16
	id        uint32
}

const noID = 0xFFFFFFFF

// aclBytes encodes entries the way the kernel returns them.
func aclBytes(version uint32, es ...ent) []byte {
	b := binary.LittleEndian.AppendUint32(nil, version)
	for _, e := range es {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

// systemdACL is what systemd leaves on a credential of a unit run as uid.
func systemdACL(uid uint32) []ent {
	return []ent{
		{aclUserObj, 4, noID}, {aclUser, 4, uid}, {aclGroupObj, 0, noID},
		{aclMask, 4, noID}, {aclOther, 0, noID},
	}
}

func TestJudgeACL(t *testing.T) {
	const uid = 61234
	with := func(base []ent, add ...ent) []ent { return append(append([]ent(nil), base...), add...) }
	without := func(tag uint16) []ent {
		var out []ent
		for _, e := range systemdACL(uid) {
			if e.tag != tag {
				out = append(out, e)
			}
		}
		return out
	}
	mod := func(tag uint16, perm uint16) []ent {
		out := systemdACL(uid)
		for i := range out {
			if out[i].tag == tag {
				out[i].perm = perm
			}
		}
		return out
	}
	for _, c := range []struct {
		name string
		acl  []byte
		want string // "" = accepted
	}{
		{"systemd's shape", aclBytes(2, systemdACL(uid)...), ""},
		{"entries in another order", aclBytes(2, ent{aclOther, 0, noID}, ent{aclMask, 4, noID}, ent{aclGroupObj, 0, noID}, ent{aclUser, 4, uid}, ent{aclUserObj, 4, noID}), ""},
		{"owner entry rw-", aclBytes(2, mod(aclUserObj, 6)...), "owner entry grants write"},
		{"owner entry r-x", aclBytes(2, mod(aclUserObj, 5)...), "owner entry grants write or execute"},
		{"owner entry ---", aclBytes(2, mod(aclUserObj, 0)...), ""},
		{"service user rw-", aclBytes(2, mod(aclUser, 6)...), "not read only"},
		{"service user r-x", aclBytes(2, mod(aclUser, 5)...), "not read only"},
		{"service user ---", aclBytes(2, mod(aclUser, 0)...), "not read only"},
		{"another user", aclBytes(2, systemdACL(uid+1)...), "not this process"},
		{"two users", aclBytes(2, with(systemdACL(uid), ent{aclUser, 4, uid + 1})...), "not this process"},
		{"same user twice", aclBytes(2, with(systemdACL(uid), ent{aclUser, 4, uid})...), "two entries for this process"},
		{"a named group", aclBytes(2, with(systemdACL(uid), ent{aclGroup, 4, 7})...), "entry for group 7"},
		{"owning group r--", aclBytes(2, mod(aclGroupObj, 4)...), "owning-group or other"},
		{"other r--", aclBytes(2, mod(aclOther, 4)...), "owning-group or other"},
		{"mask rw-", aclBytes(2, mod(aclMask, 6)...), "mask"},
		{"mask ---", aclBytes(2, mod(aclMask, 0)...), "mask"},
		{"no mask", aclBytes(2, without(aclMask)...), "without the entry 0x10"},
		{"no owner entry", aclBytes(2, without(aclUserObj)...), "without the entry 0x1"},
		{"no group entry", aclBytes(2, without(aclGroupObj)...), "without the entry 0x4"},
		{"no other entry", aclBytes(2, without(aclOther)...), "without the entry 0x20"},
		{"no named user", aclBytes(2, without(aclUser)...), "does not grant this process"},
		{"mask twice", aclBytes(2, with(systemdACL(uid), ent{aclMask, 4, noID})...), "twice"},
		{"unknown tag", aclBytes(2, with(systemdACL(uid), ent{0x40, 4, noID})...), "unknown tag"},
		{"permission bits beyond rwx", aclBytes(2, mod(aclOther, 8)...), "permission bits"},
		{"version 1", aclBytes(1, systemdACL(uid)...), "version 1"},
		{"empty", nil, "malformed"},
		{"header only", aclBytes(2), "without the entry"},
		{"short header", []byte{2, 0}, "malformed"},
		{"torn entry", append(aclBytes(2, systemdACL(uid)...), 1, 2, 3), "malformed"},
		{"oversized", append(aclBytes(2, systemdACL(uid)...), make([]byte, MaxACLSize)...), "over the"},
	} {
		got := judgeACL(c.acl, uid)
		if c.want == "" {
			if got != "" {
				t.Errorf("%s: refused: %s", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want it to contain %q", c.name, got, c.want)
		}
	}
}

// The decoder is fed the extended attribute of a file anybody could have set
// an ACL on: it must never panic and must accept only what it can name.
func FuzzJudgeACL(f *testing.F) {
	f.Add(aclBytes(2, systemdACL(61234)...), uint32(61234))
	f.Add(aclBytes(2, ent{aclGroup, 7, 7}), uint32(0))
	f.Add([]byte{}, uint32(1))
	f.Add([]byte{2, 0, 0, 0, 1}, uint32(1))
	f.Fuzz(func(t *testing.T, acl []byte, uid uint32) {
		if judgeACL(acl, uid) != "" {
			return
		}
		// Accepted: it must be exactly the five systemd entries in some order,
		// the named one being this uid with read only.
		if len(acl) != aclHeader+5*aclEntry || binary.LittleEndian.Uint32(acl) != aclVersion {
			t.Fatalf("accepted an ACL of %d bytes: %x", len(acl), acl)
		}
		for b := acl[aclHeader:]; len(b) > 0; b = b[aclEntry:] {
			tag, perm := binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:])
			switch tag {
			case aclUser:
				if perm != aclRead || binary.LittleEndian.Uint32(b[4:]) != uid {
					t.Fatalf("accepted %x for uid %d", acl, uid)
				}
			case aclUserObj, aclGroupObj, aclMask, aclOther:
				if perm&^7 != 0 || (tag != aclUserObj && tag != aclMask && perm != 0) || perm&3 != 0 {
					t.Fatalf("accepted %x", acl)
				}
			default:
				t.Fatalf("accepted tag %#x in %x", tag, acl)
			}
		}
	})
}

func TestJudgeACLNeverPanicsOnMalformedInput(t *testing.T) {
	for _, in := range [][]byte{nil, {2}, {2, 0, 0, 0, 1}, append(aclBytes(2, systemdACL(7)...), 1)} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("judgeACL(%v) panicked: %v", in, r)
				}
			}()
			if judgeACL(in, 7) == "" {
				t.Errorf("judgeACL(%v) accepted a malformed ACL", in)
			}
		}()
	}
}

package creds

import (
	"encoding/binary"
	"fmt"
)

// The shape systemd gives a credential of a unit that runs as another user
// (DynamicUser=yes, or User=, with LoadCredential= / LoadCredentialEncrypted=
// / SetCredential=), from systemd v257:
//
//   - src/core/exec-credential.c:338, write_credential() creates the file in
//     the unit's credentials directory as the manager (root), mode 0600;
//   - :346 fchmod(fd, 0400), "take away the w bit";
//   - :350-351 when the service uid is not the manager's, it calls
//     fd_add_uid_acl_permission(fd, uid, ACL_READ), which
//     src/shared/acl-util.c:448-494 implements: one ACL_USER entry for that
//     uid with read only, then calc_acl_mask_if_needed() (acl-util.c:58-86)
//     computes the mask, which is r-- here;
//   - :358-361 only when the filesystem has no ACLs (ramfs) or the ACL call is
//     refused, it falls back to fchown(fd, uid, gid), mode 0400: the process's
//     own file, which judge already accepts.
//
// So the file is root:root, and `stat` shows mode 0440 because with a POSIX ACL
// the group bits are the MASK. Its system.posix_acl_access is five entries:
// user::r--, user:<service uid>:r--, group::---, mask::r--, other::---.
// judgeACL accepts exactly that and nothing else.

// POSIX ACL xattr, as the kernel stores and returns it (little endian
// whatever the CPU): a 4 byte version, then 8 byte entries {tag, perm, id}.
const (
	// XattrACLAccess is the extended attribute that holds a file's access ACL.
	XattrACLAccess = "system.posix_acl_access"

	aclVersion = 2
	aclHeader  = 4
	aclEntry   = 8

	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20

	aclRead = 4

	// MaxACLSize bounds the xattr we read: the accepted ACL is 44 bytes, so
	// anything near this is already refused.
	MaxACLSize = 1024
)

// judgeACL decides whether acl, the raw system.posix_acl_access of a file,
// grants the process (uid) read access, and nobody else anything. It returns
// the reason for a refusal, "" for an acceptance. The ACL must hold exactly:
// user:: with no write or execute, one named user entry for uid with read
// only, group:: and other:: with nothing, and a mask of read only. A named
// group, a second named user, any write or execute bit, a duplicate or unknown
// tag, a wrong version, or a malformed or oversized value is refused.
func judgeACL(acl []byte, uid uint32) string {
	if len(acl) > MaxACLSize {
		return fmt.Sprintf("has an ACL of %d bytes, over the %d allowed", len(acl), MaxACLSize)
	}
	if len(acl) < aclHeader || (len(acl)-aclHeader)%aclEntry != 0 {
		return fmt.Sprintf("has a malformed ACL (%d bytes)", len(acl))
	}
	if v := binary.LittleEndian.Uint32(acl); v != aclVersion {
		return fmt.Sprintf("has an ACL of version %d, not %d", v, aclVersion)
	}
	var seen = map[uint16]bool{}
	named := false
	for b := acl[aclHeader:]; len(b) > 0; b = b[aclEntry:] {
		tag := binary.LittleEndian.Uint16(b)
		perm := binary.LittleEndian.Uint16(b[2:])
		id := binary.LittleEndian.Uint32(b[4:])
		if perm&^7 != 0 {
			return fmt.Sprintf("has an ACL entry with permission bits %#x", perm)
		}
		switch tag {
		case aclUserObj:
			if perm&3 != 0 {
				return "has an ACL whose owner entry grants write or execute"
			}
		case aclGroupObj, aclOther:
			if perm != 0 {
				return "has an ACL whose owning-group or other entry grants access"
			}
		case aclMask:
			if perm != aclRead {
				return fmt.Sprintf("has an ACL mask of %d, not read only", perm)
			}
		case aclUser:
			if id != uid {
				return fmt.Sprintf("has an ACL entry for user %d, not this process (uid %d)", id, uid)
			}
			if perm != aclRead {
				return fmt.Sprintf("has an ACL that gives uid %d permission %d, not read only", uid, perm)
			}
			if named {
				return "has an ACL with two entries for this process"
			}
			named = true
			continue
		case aclGroup:
			return fmt.Sprintf("has an ACL entry for group %d: only the one user may be named", id)
		default:
			return fmt.Sprintf("has an ACL entry of unknown tag %#x", tag)
		}
		if seen[tag] {
			return fmt.Sprintf("has an ACL with the entry %#x twice", tag)
		}
		seen[tag] = true
	}
	for _, t := range []uint16{aclUserObj, aclGroupObj, aclMask, aclOther} {
		if !seen[t] {
			return fmt.Sprintf("has an ACL without the entry %#x", t)
		}
	}
	if !named {
		return fmt.Sprintf("has an ACL that does not grant this process (uid %d) read access", uid)
	}
	return ""
}

// Package privsep is the boundary between the two processes of a gateway that
// separates its privileges (OpenBSD, see cmd/claimward-server).
//
// The PARENT stays root and does only what the kernel refuses anyone else: the
// WireGuard peer ioctls, the pf anchor, the tunnel MTU. The CHILD serves HTTP,
// gRPC, authenticates people and decides who may reach what, as an
// unprivileged user under pledge(2) and unveil(2). The child can ask the
// parent for exactly five things, over one socketpair, in the frames this file
// defines. Everything in the package is portable Go, so the protocol and its
// refusals are tested on every operating system; only the process glue
// (cmd/claimward-server) is OpenBSD's.
//
// The parent treats the child as hostile. It never parses what the child's
// clients sent; it validates the child's requests completely, and every
// request that fails is refused without reaching the kernel.
//
// Frame:
//
//	u32  length of what follows (big endian), 2 <= length <= MaxFrame
//	u8   protocol version (Version)
//	u8   message type
//	...  the body, length-2 bytes
//
// A frame that is oversized, short, of another version or not a message the
// parent knows ends the session (the stream cannot be trusted to be in step
// any more); a well-formed request that the parent refuses is answered with
// StatusRefused and costs the child one of its MaxRefusals.
package privsep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version. A frame of another version is a protocol
// error, never an attempt to read it.
const Version = 1

// MaxFrame bounds a frame, header excluded, before anything is allocated for it.
const MaxFrame = 8 << 20

// Type is the type of a message. Replies carry the request's type with
// ReplyFlag set.
type Type uint8

// The closed set of requests.
const (
	TypeAddPeer    Type = 1 // add (or replace) one WireGuard peer
	TypeRemovePeer Type = 2 // remove a peer this session added
	TypeSweep      Type = 3 // remove the peers a previous run left (once, first)
	TypeSetMTU     Type = 4 // set the tunnel MTU (once)
	TypeApply      Type = 5 // install the pf ruleset of the tenants
	ReplyFlag      Type = 0x80
)

func (t Type) String() string {
	switch t &^ ReplyFlag {
	case TypeAddPeer:
		return "add-peer"
	case TypeRemovePeer:
		return "remove-peer"
	case TypeSweep:
		return "sweep"
	case TypeSetMTU:
		return "set-mtu"
	case TypeApply:
		return "apply-tenants"
	}
	return fmt.Sprintf("type-%d", uint8(t))
}

// Statuses of a reply.
const (
	StatusOK      uint8 = 0
	StatusRefused uint8 = 1 // the parent will not do it: the request is not in the allowlist
	StatusFailed  uint8 = 2 // the parent tried and the kernel said no
)

// maxMessage bounds the text of an error reply.
const maxMessage = 256

// ProtocolError is a violation of the framing: the session ends.
type ProtocolError struct{ Reason string }

func (e *ProtocolError) Error() string { return "privsep: protocol error: " + e.Reason }

func protoErr(format string, a ...any) error {
	return &ProtocolError{Reason: fmt.Sprintf(format, a...)}
}

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, t Type, body []byte) error {
	if len(body)+2 > MaxFrame {
		return fmt.Errorf("privsep: %s body of %d bytes exceeds the %d-byte frame limit", t, len(body), MaxFrame)
	}
	b := make([]byte, 6+len(body))
	binary.BigEndian.PutUint32(b, uint32(2+len(body)))
	b[4] = Version
	b[5] = byte(t)
	copy(b[6:], body)
	_, err := w.Write(b) // one write: a frame is never interleaved
	return err
}

// ReadFrame reads one frame. io.EOF is returned only at a frame boundary;
// everything malformed is a *ProtocolError. The length is checked before any
// body is allocated.
func ReadFrame(r io.Reader) (Type, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, protoErr("truncated frame header")
		}
		return 0, nil, err // io.EOF at a boundary, or the transport's own error
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 2 {
		return 0, nil, protoErr("frame length %d is shorter than its header", n)
	}
	if n > MaxFrame {
		return 0, nil, protoErr("frame length %d exceeds the limit of %d", n, MaxFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, protoErr("truncated frame: %d bytes announced", n)
		}
		return 0, nil, err
	}
	if buf[0] != Version {
		return 0, nil, protoErr("protocol version %d, want %d", buf[0], Version)
	}
	return Type(buf[1]), buf[2:], nil
}

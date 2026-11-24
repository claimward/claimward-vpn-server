// A module of its own: the generator runs on an OpenBSD VM with the Go that
// the OpenBSD package collection ships (Go publishes no OpenBSD toolchain), so
// it must not inherit the server's go directive.
module github.com/claimward/claimward-vpn-server/internal/pf/abigen

go 1.21

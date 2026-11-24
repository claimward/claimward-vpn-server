// A module of its own, for the reason internal/pf/abigen is one: the generator
// runs on an OpenBSD VM with the Go that the OpenBSD package collection ships,
// so it must not inherit the server's go directive.
module github.com/claimward/claimward-vpn-server/internal/wg/abigen

go 1.21

// Package rcproof holds the OpenBSD rc.d proof: a test, built for OpenBSD and
// run as root inside the CI's real OpenBSD VMs, that installs
// deploy/openbsd/claimward_server and drives it with rcctl(8). It has no
// other content.
package rcproof

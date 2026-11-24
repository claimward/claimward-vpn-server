//go:build ignore

// gen runs `go tool cgo -godefs defs.go` on THIS host, which must be OpenBSD,
// and writes zwg_openbsd_<arch>.go into the directory given as the only
// argument.
//
//	go run gen.go ../gen
//
// Same contract as internal/pf/abigen: the CI lane regenerates on each
// supported release and architecture and compares with the committed file.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	if len(os.Args) != 2 || runtime.GOOS != "openbsd" {
		fmt.Fprintln(os.Stderr, "usage (on OpenBSD): go run gen.go <output directory>")
		os.Exit(2)
	}
	var out, errb bytes.Buffer
	cmd := exec.Command("go", "tool", "cgo", "-godefs", "defs.go")
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "cgo -godefs: %v\n%s", err, errb.String())
		os.Exit(1)
	}
	src, err := format.Source([]byte(strings.TrimSpace(out.String())))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gofmt:", err)
		os.Exit(1)
	}
	// The release is deliberately not written into the file: 7.9 and 8.0 share
	// one layout, and the lane proves it by comparing bytes.
	dest := filepath.Join(os.Args[1], "zwg_openbsd_"+runtime.GOARCH+".go")
	if err := os.WriteFile(dest, src, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

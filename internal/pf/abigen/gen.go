//go:build ignore

// gen runs `go tool cgo -godefs defs.go` on THIS host, which must be OpenBSD,
// and writes the formatted result to the path given as the only argument.
//
//	go run gen.go ../ztypes_openbsd_amd64.go
//
// The first line of the output records the release and architecture it was
// generated for, so the CI lane can regenerate on each supported release and
// compare with the committed file.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func main() {
	if len(os.Args) != 2 || runtime.GOOS != "openbsd" {
		fmt.Fprintln(os.Stderr, "usage (on OpenBSD): go run gen.go <output.go>")
		os.Exit(2)
	}
	var out, errb bytes.Buffer
	cmd := exec.Command("go", "tool", "cgo", "-godefs", "defs.go")
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "cgo -godefs: %v\n%s", err, errb.String())
		os.Exit(1)
	}
	// cgo prints "// cgo -godefs defs.go" and "// Code generated ..." first.
	body := strings.TrimSpace(out.String())
	src, err := format.Source([]byte(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gofmt:", err)
		os.Exit(1)
	}
	// The release is deliberately NOT written into the file: 7.9 and 8.0
	// share one layout, and the lane proves it by regenerating on each and
	// comparing the bytes with the committed file.
	if err := os.WriteFile(os.Args[1], append(src, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

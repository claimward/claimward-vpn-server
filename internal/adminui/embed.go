// Package adminui embeds the built admin WebUI (Svelte + DaisyUI). Regenerate the
// dist with: cd admin-ui && npm install && npm run build.
package adminui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the embedded built UI rooted at dist/.
func FS() fs.FS {
	sub, _ := fs.Sub(dist, "dist")
	return sub
}

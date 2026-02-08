package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFiles embed.FS

// StaticFS returns an http.FileSystem for the embedded static files.
func StaticFS() http.FileSystem {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}

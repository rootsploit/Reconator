package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// Assets embeds the pre-built web dashboard
// This allows the binary to include the UI without requiring separate deployment
//
//go:embed dist
var Assets embed.FS

// GetFS returns the filesystem for serving web assets
// Returns the embedded dist directory contents
func GetFS() (http.FileSystem, error) {
	// Get the dist subdirectory from embedded assets
	distFS, err := fs.Sub(Assets, "dist")
	if err != nil {
		return nil, err
	}
	return http.FS(distFS), nil
}

// HasAssets checks if web assets are embedded in the binary
func HasAssets() bool {
	// Check if dist/index.html exists
	_, err := Assets.Open("dist/index.html")
	return err == nil
}

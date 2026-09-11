package ui

import "embed"

// DistFS contains the production dashboard assets built by Vite into ui/dist.
// This allows Go binaries (like cmd/waf-api) to embed the single-page application
// cleanly without requiring relative parent paths or breaking package boundaries.
//
//go:embed all:dist
var DistFS embed.FS

// Command yolonot is the CLI entry point. All logic lives in
// internal/yolonot; this file is a thin shim so `go install` produces
// a `yolonot` binary.
package main

import "github.com/sezaakgun/yolonot/internal/yolonot"

func main() { yolonot.Run() }

//go:build mobilebind

package mobilecore

// Keeps golang.org/x/mobile in go.mod so `gomobile bind` (which needs
// the bind package resolvable in this module) is reproducible from a
// fresh checkout. Never part of a real build — gomobile injects its
// own bind wiring; this tag is satisfied nowhere.
import _ "golang.org/x/mobile/bind"

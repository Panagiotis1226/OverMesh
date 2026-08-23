//go:build !windows

package main

import "fmt"

// serviceCommand: Windows-only; Linux uses the systemd unit from the
// deb/rpm packages, macOS uses launchd/Homebrew services.
func serviceCommand(cmd string) error {
	return fmt.Errorf("-service is Windows-only (Linux: systemctl enable --now overmeshd; macOS: brew services)")
}

func runAsServiceIfNeeded(start, stop func()) bool { return false }

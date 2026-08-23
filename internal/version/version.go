// Package version exposes build metadata stamped in via -ldflags.
package version

import "runtime/debug"

// Version is the release version, set at build time via
// -ldflags "-X github.com/panagiotis1226/overmesh/internal/version.Version=v0.1.0".
var Version = "dev"

// Long returns the version, appending the VCS revision when the version
// was not stamped at build time.
func Long() string {
	if Version != "dev" {
		return Version
	}
	rev := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 8 {
				rev = "-" + s.Value[:8]
			}
		}
	}
	return Version + rev
}

package meshdns

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const (
	beginMarker = "# BEGIN overmesh dns"
	endMarker   = "# END overmesh dns"
	resolvConf  = "/etc/resolv.conf"
)

// ConfigureOS points the OS at the mesh resolver for the zone and adds it
// as a search domain so bare hostnames resolve. Prefers systemd-resolved
// (per-interface split DNS); falls back to a marked block at the top of
// /etc/resolv.conf.
func ConfigureOS(iface, domain string, resolver netip.Addr, logf func(string, ...any)) error {
	if haveResolved() {
		steps := [][]string{
			{"resolvectl", "dns", iface, resolver.String()},
			// A non-~ domain is both a search domain (bare names) and a
			// routing domain (*.domain goes to this interface's server).
			{"resolvectl", "domain", iface, domain},
			{"resolvectl", "default-route", iface, "false"},
		}
		for _, cmd := range steps {
			if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %v: %s", strings.Join(cmd, " "), err, out)
			}
		}
		logf("meshdns: configured via systemd-resolved (iface %s, domain %s)", iface, domain)
		return nil
	}
	return configureResolvConf(domain, resolver, logf)
}

// DeconfigureOS undoes ConfigureOS.
func DeconfigureOS(iface string, logf func(string, ...any)) {
	if haveResolved() {
		_ = exec.Command("resolvectl", "revert", iface).Run()
		return
	}
	restoreResolvConf(logf)
}

func haveResolved() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	// resolvectl exists on systems where resolved isn't running; probe.
	return exec.Command("resolvectl", "status").Run() == nil
}

// configureResolvConf prepends a marked block: our nameserver first (it
// REFUSES out-of-zone queries, so libc falls through to the original
// servers) and a merged search line so bare hostnames expand.
func configureResolvConf(domain string, resolver netip.Addr, logf func(string, ...any)) error {
	orig, err := os.ReadFile(resolvConf)
	if err != nil {
		return err
	}
	content := stripMarkedBlock(string(orig))

	// Merge existing search domains after ours (libc uses the last
	// `search` line, so ours must carry the full list).
	var existing []string
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && (f[0] == "search" || f[0] == "domain") {
			existing = append(existing, f[1:]...)
		}
	}
	search := domain
	for _, e := range existing {
		if e != domain {
			search += " " + e
		}
	}

	block := fmt.Sprintf("%s\nnameserver %s\nsearch %s\n%s\n", beginMarker, resolver, search, endMarker)
	if err := os.WriteFile(resolvConf, []byte(block+content), 0o644); err != nil {
		return err
	}
	logf("meshdns: configured via %s (search %s)", resolvConf, domain)
	return nil
}

func restoreResolvConf(logf func(string, ...any)) {
	orig, err := os.ReadFile(resolvConf)
	if err != nil {
		return
	}
	stripped := stripMarkedBlock(string(orig))
	if stripped != string(orig) {
		if err := os.WriteFile(resolvConf, []byte(stripped), 0o644); err != nil {
			logf("meshdns: restoring %s: %v", resolvConf, err)
		}
	}
}

func stripMarkedBlock(s string) string {
	for {
		start := strings.Index(s, beginMarker)
		if start < 0 {
			return s
		}
		end := strings.Index(s, endMarker)
		if end < 0 {
			return s[:start]
		}
		end += len(endMarker)
		if end < len(s) && s[end] == '\n' {
			end++
		}
		s = s[:start] + s[end:]
	}
}

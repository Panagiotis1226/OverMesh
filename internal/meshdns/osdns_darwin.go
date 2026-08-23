package meshdns

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const restoreFile = "/var/lib/overmesh/dns-search-restore.json"

// ConfigureOS on macOS does two things:
//  1. /etc/resolver/<domain>: routes *.<domain> queries to the mesh
//     resolver (the supported macOS split-DNS mechanism).
//  2. networksetup search domains: appends <domain> to every network
//     service so BARE hostnames ("ps-iphone") expand to
//     ps-iphone.<domain> — the Tailscale-style experience. Originals are
//     saved for restore.
func ConfigureOS(_ /*iface*/, domain string, resolver netip.Addr, logf func(string, ...any)) error {
	if err := os.MkdirAll("/etc/resolver", 0o755); err != nil {
		return err
	}
	conf := fmt.Sprintf("nameserver %s\nsearch_order 1\n", resolver)
	if err := os.WriteFile("/etc/resolver/"+domain, []byte(conf), 0o644); err != nil {
		return err
	}

	services, err := listNetworkServices()
	if err != nil {
		logf("meshdns: listing network services: %v (bare hostnames may need the FQDN)", err)
		return nil
	}
	saved := map[string][]string{}
	for _, svc := range services {
		cur, err := getSearchDomains(svc)
		if err != nil {
			continue
		}
		if contains(cur, domain) {
			continue
		}
		saved[svc] = cur
		if err := setSearchDomains(svc, append(append([]string{}, cur...), domain)); err != nil {
			logf("meshdns: search domains on %q: %v", svc, err)
		}
	}
	if len(saved) > 0 {
		_ = os.MkdirAll("/var/lib/overmesh", 0o700)
		if data, err := json.Marshal(saved); err == nil {
			_ = os.WriteFile(restoreFile, data, 0o600)
		}
	}
	logf("meshdns: configured /etc/resolver/%s + search domains", domain)
	return nil
}

// DeconfigureOS undoes ConfigureOS.
func DeconfigureOS(_ string, logf func(string, ...any)) {
	entries, err := os.ReadDir("/etc/resolver")
	if err == nil {
		for _, e := range entries {
			// Our files end in the mesh TLD; be conservative and only
			// remove files whose content points at an overlay address.
			path := "/etc/resolver/" + e.Name()
			data, err := os.ReadFile(path)
			if err == nil && strings.Contains(string(data), "search_order 1") &&
				strings.Contains(string(data), "nameserver 100.") {
				_ = os.Remove(path)
			}
		}
	}
	data, err := os.ReadFile(restoreFile)
	if err != nil {
		return
	}
	var saved map[string][]string
	if json.Unmarshal(data, &saved) != nil {
		return
	}
	for svc, domains := range saved {
		if err := setSearchDomains(svc, domains); err != nil {
			logf("meshdns: restoring search domains on %q: %v", svc, err)
		}
	}
	_ = os.Remove(restoreFile)
}

func listNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// First line is a notice; disabled services are prefixed with *.
		if line == "" || strings.Contains(line, "denotes that") || strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs, nil
}

func getSearchDomains(svc string) ([]string, error) {
	out, err := exec.Command("networksetup", "-getsearchdomains", svc).Output()
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(out))
	if s == "" || strings.Contains(s, "There aren't any") {
		return nil, nil
	}
	return strings.Fields(s), nil
}

func setSearchDomains(svc string, domains []string) error {
	args := []string{"-setsearchdomains", svc}
	if len(domains) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, domains...)
	}
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

//go:build linux

package meshdns

import "testing"

func TestStripMarkedBlock(t *testing.T) {
	in := beginMarker + "\nnameserver 100.96.0.1\nsearch default.mesh\n" + endMarker + "\nnameserver 8.8.8.8\n"
	if got := stripMarkedBlock(in); got != "nameserver 8.8.8.8\n" {
		t.Fatalf("strip: %q", got)
	}
	if got := stripMarkedBlock("nameserver 1.1.1.1\n"); got != "nameserver 1.1.1.1\n" {
		t.Fatalf("no-op strip changed content: %q", got)
	}
}

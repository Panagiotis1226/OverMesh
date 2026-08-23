package store

import "testing"

func TestACLRoundTripAndValidation(t *testing.T) {
	s := open(t)
	nw := testNetwork(t, s)

	// Empty by default.
	rules, err := s.ACL(nw.ID)
	if err != nil || len(rules) != 0 {
		t.Fatalf("fresh ACL: %v, %v", rules, err)
	}

	set := []ACLRule{
		{Action: "deny", SrcIDs: []int64{1}, DstIDs: []int64{2}, Protocol: "tcp", Ports: []string{"22"}},
		{Action: "allow", Protocol: "", Ports: nil}, // any->any allow
	}
	if err := s.SetACL(nw.ID, set); err != nil {
		t.Fatal(err)
	}
	rules, err = s.ACL(nw.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Action != "deny" || rules[1].Action != "allow" {
		t.Fatalf("order/content mismatch: %+v", rules)
	}
	if rules[0].Ports[0] != "22" || rules[0].SrcIDs[0] != 1 {
		t.Fatalf("rule fields lost: %+v", rules[0])
	}

	// Replace-all semantics.
	if err := s.SetACL(nw.ID, nil); err != nil {
		t.Fatal(err)
	}
	rules, _ = s.ACL(nw.ID)
	if len(rules) != 0 {
		t.Fatalf("SetACL(nil) left %d rules", len(rules))
	}

	// Validation.
	if err := s.SetACL(nw.ID, []ACLRule{{Action: "yolo"}}); err == nil {
		t.Fatal("bad action accepted")
	}
	if err := s.SetACL(nw.ID, []ACLRule{{Action: "allow", Protocol: "gre"}}); err == nil {
		t.Fatal("bad protocol accepted")
	}
}

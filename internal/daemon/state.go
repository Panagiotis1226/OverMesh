package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/panagiotis1226/overmesh/internal/key"
)

// State is the daemon's persistent identity and last-known session,
// stored as 0600 JSON in the state directory. The machine key is the
// device's permanent identity; losing it means re-enrolling with a fresh
// setup key.
type State struct {
	MachinePrivateHex string `json:"machine_private_hex"`
	NodePrivateHex    string `json:"node_private_hex"`
	Server            string `json:"server,omitempty"`
	DesiredUp         bool   `json:"desired_up,omitempty"`
	// AdvertiseRoutes are CIDRs this node offers to route for the mesh
	// (0.0.0.0/0 + ::/0 = exit-node offer); re-sent on every register.
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`
	// ExitNode is the hostname of the peer all traffic should egress
	// through ("" = none).
	ExitNode string `json:"exit_node,omitempty"`

	machinePriv key.MachinePrivate
	nodePriv    key.NodePrivate
}

const stateFile = "overmeshd.json"

// LoadOrCreateState reads the state file, generating fresh keys on first
// run.
func LoadOrCreateState(dir string) (*State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, stateFile)
	st := &State{}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, st); err != nil {
			return nil, fmt.Errorf("corrupt state file %s: %w", path, err)
		}
	case os.IsNotExist(err):
		mk, err := key.NewMachine()
		if err != nil {
			return nil, err
		}
		nk, err := key.NewNode()
		if err != nil {
			return nil, err
		}
		st.MachinePrivateHex = mk.Hex()
		st.NodePrivateHex = nk.Hex()
	default:
		return nil, err
	}

	if st.machinePriv, err = key.MachinePrivateFromHex(st.MachinePrivateHex); err != nil {
		return nil, err
	}
	if st.nodePriv, err = key.NodePrivateFromHex(st.NodePrivateHex); err != nil {
		return nil, err
	}
	return st, st.Save(dir)
}

// Save writes the state file atomically with owner-only permissions.
func (st *State) Save(dir string) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateFile))
}

// MachineKey returns the device identity private key.
func (st *State) MachineKey() key.MachinePrivate { return st.machinePriv }

// NodeKey returns the WireGuard private key.
func (st *State) NodeKey() key.NodePrivate { return st.nodePriv }

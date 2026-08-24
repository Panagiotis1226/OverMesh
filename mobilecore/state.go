package mobilecore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/panagiotis1226/overmesh/internal/key"
)

// state is the device's persistent identity — deliberately minimal
// (the app keeps its own preferences). The machine key is the
// permanent identity; losing it means re-enrolling with a setup key.
type state struct {
	machine key.MachinePrivate
	node    key.NodePrivate
}

type stateFile struct {
	MachinePrivateHex string `json:"machine_private_hex"`
	NodePrivateHex    string `json:"node_private_hex"`
}

const stateName = "mobilecore.json"

func loadOrCreateState(dir string) (*state, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, stateName)
	var sf stateFile
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &sf); err != nil {
			return nil, fmt.Errorf("corrupt state %s: %w", path, err)
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
		sf.MachinePrivateHex = mk.Hex()
		sf.NodePrivateHex = nk.Hex()
		out, _ := json.MarshalIndent(sf, "", "  ")
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	st := &state{}
	if st.machine, err = key.MachinePrivateFromHex(sf.MachinePrivateHex); err != nil {
		return nil, err
	}
	if st.node, err = key.NodePrivateFromHex(sf.NodePrivateHex); err != nil {
		return nil, err
	}
	return st, nil
}

//go:build !linux && !darwin

package wgengine

import "errors"

var errUnsupported = errors.New("wgengine: platform not supported yet (Windows lands in Phase 8, mobile in Phase 9)")

func newKernel(Options) (Engine, error)    { return nil, errUnsupported }
func newUserspace(Options) (Engine, error) { return nil, errUnsupported }

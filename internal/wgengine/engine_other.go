//go:build !linux && !darwin && !windows

package wgengine

import "errors"

var errUnsupported = errors.New("wgengine: platform not supported yet (mobile lands in Phase 9)")

func newKernel(Options) (Engine, error)    { return nil, errUnsupported }
func newUserspace(Options) (Engine, error) { return nil, errUnsupported }

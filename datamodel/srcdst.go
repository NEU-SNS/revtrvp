package datamodel

import "time"

// SrcDst represents a source destination pair
type SrcDst struct {
	Addr         uint32
	Dst          uint32
	Alias        bool
	Stale        time.Duration
	Src          uint32
	IgnoreSource bool
}

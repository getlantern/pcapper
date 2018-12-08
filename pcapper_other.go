// +build !linux

package pcapper

import (
	"time"
)

// StartCapturing doesn't do anything on this platform.
func StartCapturing(interfaceName string, dir string, numIPs int, packetsPerIP int, snapLen int, timeout time.Duration) error {
}

// Dump doesn't do anything on this platform.
func Dump(prefix string, ip string) {}

// DumpAll doesn't do anything on this platform.
func DumpAll(prefix string) {}

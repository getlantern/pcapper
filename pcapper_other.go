// +build !linux

package pcapper

// StartCapturing doesn't do anything on this platform.
func StartCapturing(interfaceName string, dir string, numIPs int, packetsPerIP int) {
}

// Dump doesn't do anything on this platform.
func Dump(prefix string, ip string) error {
	return nil
}

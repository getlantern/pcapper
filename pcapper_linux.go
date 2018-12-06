// Package pcapper provides a facility for continually capturing pcaps at the ip
// level and then dumping those for specific IPs when the time comes.
package pcapper

import (
	"net"
	"os"
	"path/filepath"

	"github.com/getlantern/golog"
	"github.com/getlantern/ring"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/hashicorp/golang-lru"
)

const (
	snapLen = 1600
)

var (
	log = golog.LoggerFor("pcapper")

	dumpRequests = make(chan string, 10000)
)

// StartCapturing starts capturing packets from the named network interface. It
// will dump packets into files at <dir>/<ip>.pcap. It will store data for up to
// <numIPs> of the most recently active IPs in memory, and it will store up to
// <packetsPerIP> packets per IP.
func StartCapturing(interfaceName string, dir string, numIPs int, packetsPerIP int) error {
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return log.Errorf("Unable to determine interface addresses: %v", err)
	}
	localInterfaces := make(map[string]bool, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		localInterfaces[ifAddr.String()] = true
	}

	handle, err := pcap.OpenLive(interfaceName, snapLen, true, pcap.BlockForever)
	if err != nil {
		return log.Errorf("Unable to open %v for packet capture: %v", interfaceName, err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	buffersByIP, err := lru.New(numIPs)
	if err != nil {
		return log.Errorf("Unable to initialize cache: %v", err)
	}

	getBufferByIP := func(ip string) ring.List {
		_buffer, found := buffersByIP.Get(ip)
		if !found {
			_buffer = ring.NewList(packetsPerIP)
			buffersByIP.Add(ip, _buffer)
		}
		return _buffer.(ring.List)
	}

	capturePacket := func(dstIP string, srcIP string, packet gopacket.Packet) {
		if !localInterfaces[dstIP] {
			getBufferByIP(dstIP).Push(packet)
		} else if !localInterfaces[srcIP] {
			getBufferByIP(srcIP).Push(packet)
		}
	}

	dumpPacketsForIP := func(ip string) error {
		log.Debugf("Attempting to dump pcaps for %v", ip)

		defer func() {
			buffersByIP.Remove(ip)
		}()

		buffers := getBufferByIP(ip)
		if buffers.Len() == 0 {
			log.Debugf("No pcaps to dump for %v", ip)
			return nil
		}

		pcapsFileName := filepath.Join(dir, ip+".pcap")
		newFile := false
		pcapsFile, err := os.OpenFile(pcapsFileName, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			if !os.IsNotExist(err) {
				return log.Errorf("Unable to open pcap file %v: %v", pcapsFileName, err)
			}
			pcapsFile, err = os.Create(pcapsFileName)
			if err != nil {
				return log.Errorf("Unable to create pcap file %v: %v", pcapsFileName, err)
			}
			newFile = true
		}
		pcaps := pcapgo.NewWriter(pcapsFile)
		if newFile {
			pcaps.WriteFileHeader(snapLen, layers.LinkTypeEthernet)
		}

		dumpPacket := func(dstIP string, srcIP string, packet gopacket.Packet) {
			if dstIP == ip || srcIP == ip {
				pcaps.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}
		}

		buffers.IterateForward(func(_packet interface{}) bool {
			if _packet == nil {
				// TODO: figure out why we need this guard condition, since we shouldn't
				return false
			}
			packet := _packet.(gopacket.Packet)
			nl := packet.NetworkLayer()
			switch t := nl.(type) {
			case *layers.IPv4:
				dumpPacket(t.DstIP.String(), t.SrcIP.String(), packet)
			case *layers.IPv6:
				dumpPacket(t.DstIP.String(), t.SrcIP.String(), packet)
			}
			return true
		})

		pcapsFile.Close()
		log.Debugf("Logged pcaps for %v to %v", ip, pcapsFile.Name())
		return nil
	}

	go func() {
		for {
			select {
			case packet := <-packetSource.Packets():
				nl := packet.NetworkLayer()
				switch t := nl.(type) {
				case *layers.IPv4:
					capturePacket(t.DstIP.String(), t.SrcIP.String(), packet)
				case *layers.IPv6:
					capturePacket(t.DstIP.String(), t.SrcIP.String(), packet)
				}
			case ip := <-dumpRequests:
				dumpPacketsForIP(ip)
			}
		}
	}()

	return nil
}

// Dump dumps captured packets to/from the given ip to disk.
func Dump(ip string) {
	select {
	case dumpRequests <- ip:
		// ok
	default:
		log.Errorf("Too many pending dump requests, ignoring request for %v", ip)
	}
}

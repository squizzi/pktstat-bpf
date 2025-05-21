// @license
// Copyright (C) 2024  Dinko Korunic
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/goccy/go-json"
)

// processMap generates statEntry objects from an ebpf.Map.
//
// Parameters:
//
//	m *ebpf.Map - the ebpf map to process
func processMap(m *ebpf.Map, sortFunc func([]statEntry)) ([]statEntry, error) {
	var (
		key counterStatkey
		val counterStatvalue
	)

	stats := make([]statEntry, 0, m.MaxEntries())
	iter := m.Iterate()

	// Parse internal networks if external-only filtering is enabled
	var internalNetworkPrefixes []netip.Prefix
	if externalOnly != nil && *externalOnly && internalNetworks != nil {
		var err error
		internalNetworkPrefixes, err = parseInternalNetworks(*internalNetworks)
		if err != nil {
			return nil, fmt.Errorf("error parsing internal networks: %w", err)
		}
	}

	// build statEntry slice converting data where needed
	for iter.Next(&key, &val) {
		srcIP := bytesToAddr(key.Srcip.In6U.U6Addr8)
		dstIP := bytesToAddr(key.Dstip.In6U.U6Addr8)

		// Check if this IP is a DNS service
		isDNSTraffic := false
		dstIPStr := dstIP.String()
		srcIPStr := srcIP.String()

		for _, dnsIP := range dnsServiceIPs {
			if dstIPStr == dnsIP || srcIPStr == dnsIP {
				isDNSTraffic = true
				break
			}
		}

		// Skip if external-only is enabled and destination IP is internal
		// But always include DNS traffic even with externalOnly flag
		if externalOnly != nil && *externalOnly && !isDNSTraffic && isInternalIP(dstIP, internalNetworkPrefixes) {
			continue
		}

		entry := statEntry{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Proto:     protoToString(key.Proto),
			SrcPort:   key.SrcPort,
			DstPort:   key.DstPort,
			Pid:       key.Pid,
			Comm:      comm2String(key.Comm[:]),
			Timestamp: time.Now(),
		}

		// Set service name based on destination port
		if key.Proto == 6 || key.Proto == 17 { // TCP or UDP
			entry.LikelyService = portToLikelyServiceName(key.DstPort)
		}

		// Look up pod names if Kubernetes support is enabled
		if kubeconfig != nil && *kubeconfig != "" && kubeClient != nil {
			entry.SourcePod = lookupPodForIP(srcIP)
			entry.DstPod = lookupPodForIP(dstIP)
		}

		stats = append(stats, entry)
	}

	sortFunc(stats)

	return stats, iter.Err()
}

// timeDateSort sorts a slice of statEntry objects by their Timestamp field in ascending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func timeDateSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Timestamp.Before(stats[j].Timestamp)
	})
}

// srcIPSort sorts a slice of statEntry objects by their SrcIP field in ascending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func srcIPSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].SrcIP.Compare(stats[j].SrcIP) < 0
	})
}

// dstIPSort sorts a slice of statEntry objects by their DstIP field in ascending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func dstIPSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].DstIP.Compare(stats[j].DstIP) < 0
	})
}

// outputJSON formats the provided statEntry slice into a JSON string.
//
// The JSON is created using the encoding/json package, marshaling the statEntry
// slice into a JSON array. The output is a string.
//
// Parameters:
//
//	m []statEntry - the statEntry slice to be formatted
//
// Returns:
//
//	string - the JSON string representation of m
func outputJSON(m []statEntry) string {
	out, _ := json.Marshal(m)

	return string(out)
}

// outputPlain formats a slice of statEntry objects into a plain text string.
// Each line represents a network flow with the following information:
//   - Timestamp
//   - Protocol (TCP, UDP, ICMPv4, IPv6-ICMP)
//   - Source IP and port
//   - Destination IP and port
//   - ICMP type and code (for ICMP protocols)
//   - Process ID (PID)
//   - Command name (comm)
//
// The output is sorted chronologically by timestamp.
//
// Parameters:
//
//	m []statEntry - the statEntry slice to be formatted
//
// Returns:
//
//	string - the formatted string
func outputPlain(m []statEntry) string {
	var sb strings.Builder

	for _, v := range m {
		switch v.Proto {
		case "ICMPv4", "IPv6-ICMP":
			sb.WriteString(fmt.Sprintf("timestamp: %v, proto: %v, src: %v, dst: %v, type: %d, code: %d",
				v.Timestamp, v.Proto, v.SrcIP, v.DstIP, v.SrcPort, v.DstPort))
		default:
			sb.WriteString(fmt.Sprintf("timestamp: %v, proto: %v, src: %v:%d, dst: %v:%d",
				v.Timestamp, v.Proto, v.SrcIP, v.SrcPort, v.DstIP, v.DstPort))
		}

		if v.Pid > 0 {
			sb.WriteString(fmt.Sprintf(", pid: %d", v.Pid))
		}

		if v.Comm != "" {
			sb.WriteString(fmt.Sprintf(", comm: %v", v.Comm))
		}

		// Add DNS origin information if available
		if v.DNSOriginPid > 0 || v.DNSOriginComm != "" || v.DNSOriginPod != "" {
			sb.WriteString(" [DNS Origin:")
			if v.DNSOriginPid > 0 {
				sb.WriteString(fmt.Sprintf(" pid: %d", v.DNSOriginPid))
			}
			if v.DNSOriginComm != "" {
				sb.WriteString(fmt.Sprintf(" comm: %s", v.DNSOriginComm))
			}
			if v.DNSOriginPod != "" {
				sb.WriteString(fmt.Sprintf(" pod: %s", v.DNSOriginPod))
			}
			sb.WriteString("]")
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

// comm2String converts a byte slice to a string, trimming any null bytes.
//
// It takes a byte slice as its parameter and returns a string.
// If the byte slice is empty, the function returns the string "kernel".
// Otherwise, it creates a new byte slice, copies the input byte slice into it,
// trims any null bytes from the end of the slice, and returns the result as a string.
func comm2String(bs []int8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}

	// trim excess NULLs
	b = bytes.Trim(b, "\x00")

	return string(b)
}

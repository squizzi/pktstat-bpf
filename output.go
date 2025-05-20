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

		// Skip if external-only is enabled and destination IP is internal
		if externalOnly != nil && *externalOnly && isInternalIP(dstIP, internalNetworkPrefixes) {
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

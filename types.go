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
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
)

type statEntry struct {
	SrcIP         netip.Addr `json:"srcIp"`
	DstIP         netip.Addr `json:"dstIp"`
	Proto         string     `json:"proto"`
	Comm          string     `json:"comm,omitempty"`
	Pid           int32      `json:"pid,omitempty"`
	SrcPort       uint16     `json:"srcPort"`
	DstPort       uint16     `json:"dstPort"`
	LikelyService string     `json:"likelyService,omitempty"`
	SourcePod     string     `json:"sourcePod,omitempty"`
	DstPod        string     `json:"dstPod,omitempty"`
	Timestamp     time.Time  `json:"timestamp"`
	// DNS origin tracking fields
	DNSOriginPid  int32  `json:"dnsOriginPid,omitempty"`
	DNSOriginComm string `json:"dnsOriginComm,omitempty"`
	DNSOriginPod  string `json:"dnsOriginPod,omitempty"`
}

// DNS event from eBPF
type dnsLookupEvent struct {
	AddrType uint32    // Address type (AF_INET or AF_INET6)
	IP       [16]byte  // IP address (IPv4 or IPv6)
	Host     [252]byte // Hostname
	Pid      int32     // Process ID
	Comm     [16]byte  // Process command
}

// DNS mapping entry to store hostname to IP mappings
type dnsMapping struct {
	Hostname    string     // The hostname that was resolved
	IP          netip.Addr // The IP address it resolved to
	Pid         int32      // Process ID that made the request
	Comm        string     // Process command that made the request
	Timestamp   time.Time  // When the resolution occurred
	PodName     string     // Pod name if in Kubernetes environment
	AddressType uint32     // AF_INET or AF_INET6
}

type kprobeHook struct {
	prog   *ebpf.Program
	kprobe string
}

type uprobeHook struct {
	prog      *ebpf.Program
	probeType string // "uretprobe" or "uprobe"
	library   string // Path to the shared library containing the symbol
	symbol    string // Name of the function to attach to
	isReturn  bool   // True for uretprobe (function return), false for uprobe (function entry)
}

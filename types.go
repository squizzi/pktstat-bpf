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

// mergedDNSEntry represents a merged view of internal and external DNS queries
type mergedDNSEntry struct {
	// Original requestor (pod/client) information
	OriginalSrcIP   string    `json:"originalSrcIp"`
	OriginalSrcPort uint16    `json:"originalSrcPort"`
	OriginalPod     string    `json:"originalPod,omitempty"`
	OriginalComm    string    `json:"originalComm,omitempty"`
	OriginalPid     int32     `json:"originalPid,omitempty"`
	Timestamp       time.Time `json:"timestamp"`

	// DNS server information
	DNSServerIP   string `json:"dnsServerIp"`
	DNSServerPod  string `json:"dnsServerPod,omitempty"`
	DNSServerComm string `json:"dnsServerComm,omitempty"`
	DNSServerPid  int32  `json:"dnsServerPid,omitempty"`

	// External query information
	ExternalDstIP   string `json:"externalDstIp,omitempty"`
	ExternalDstPort uint16 `json:"externalDstPort,omitempty"`
	Proto           string `json:"proto"`
	LikelyService   string `json:"likelyService,omitempty"`

	// DNS query information
	QueryName string `json:"queryName,omitempty"` // The domain name being queried
}

type kprobeHook struct {
	prog   *ebpf.Program
	kprobe string
}

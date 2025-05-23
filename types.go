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

type kprobeHook struct {
	prog   *ebpf.Program
	kprobe string
}

type uprobeHook struct {
	prog   *ebpf.Program
	symbol string // Name of the function to attach to
}

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

// dnsOriginMapping stores a mapping between a hostname and IP with a timestamp
type dnsOriginMapping struct {
	Hostname  string
	IP        string
	Timestamp time.Time
}

// dnsOrigin stores information about the original process that initiated a DNS request
type dnsOrigin struct {
	SrcIP     string
	SrcPort   uint16
	Pid       uint32
	Comm      string
	Timestamp time.Time
	PodName   string
}

// dnsLookupEvent represents a DNS lookup event
type dnsLookupEvent struct {
	AddrType uint32
	IP       [16]uint8
	Host     [252]byte
	Pid      uint32
	Comm     [16]byte
}

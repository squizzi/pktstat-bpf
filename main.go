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
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Global variables for DNS tracking
var (
	// Track DNS service IPs
	dnsServiceIPs []string

	// Maps to track DNS requests and their origins
	dnsRequestOrigins = make(map[string]*dnsOrigin) // key: "srcIP:srcPort-dstIP:dstPort", value: origin info
	dnsRequestsMutex  = &sync.RWMutex{}
)

// dnsOrigin stores information about the original process that initiated a DNS request
type dnsOrigin struct {
	SrcIP     string
	SrcPort   uint16
	Pid       uint32
	Comm      string
	Timestamp time.Time
	PodName   string
}

func main() {
	parseFlags()

	// Remove resource limits for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removing memlock: %v", err)
	}

	// Initialize Kubernetes client if kubeconfig is provided
	if kubeconfig != nil && *kubeconfig != "" {
		if err := initKubernetesClient(); err != nil {
			log.Fatalf("Error initializing Kubernetes client: %v", err)
		}

		// Start cache cleanup goroutine
		go cleanupIPToPodCache()

		// Detect DNS services in the cluster
		detectDNSServices()
	}

	// Load the compiled eBPF ELF and load it into the kernel
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatalf("Error loading eBPF objects: %v", err)
	}
	defer func() { _ = objs.Close() }()

	var links []link.Link

	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	hooks := []kprobeHook{
		{kprobe: "tcp_sendmsg", prog: objs.TcpSendmsg},
		{kprobe: "tcp_cleanup_rbuf", prog: objs.TcpCleanupRbuf},
		{kprobe: "ip_send_skb", prog: objs.IpSendSkb},
		{kprobe: "ip_local_out", prog: objs.IpLocalOutFn},
		{kprobe: "ip_output", prog: objs.IpOutputFn},
		{kprobe: "skb_consume_udp", prog: objs.SkbConsumeUdp},
		{kprobe: "__icmp_send", prog: objs.IcmpSend},
		{kprobe: "icmp6_send", prog: objs.Icmp6Send},
		{kprobe: "icmp_rcv", prog: objs.IcmpRcv},
		{kprobe: "icmpv6_rcv", prog: objs.Icmpv6Rcv},
	}

	links = startKProbes(hooks, links)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Create a ticker to process the map every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Set up signal handler
	go func() {
		s := <-signalCh
		_, _ = fmt.Fprintf(os.Stderr, "Received %v signal, exiting...\n", s)
		cancel()
	}()

	// Track seen entries to avoid duplicates
	seenEntries := make(map[string]bool)

	// Run the main loop
	for {
		select {
		case <-ticker.C:
			// Process the map
			entries, err := processMap(objs.PktCount, timeDateSort)
			if err != nil {
				log.Printf("Error reading eBPF map: %v", err)
				continue
			}

			// Track DNS queries and their origins
			trackDNSQueries(entries)

			// Enrich with DNS origin information
			enrichWithDNSOrigins(entries)

			// Filter out entries we've already seen
			var newEntries []statEntry
			for _, entry := range entries {
				// Create unique keys for tracking seen entries
				// For regular tracking (with timestamp)
				timeKey := fmt.Sprintf("%s:%d->%s:%d:%s:%d:%s:%s",
					entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort,
					entry.Proto, entry.Pid, entry.Comm, entry.Timestamp.Format(time.RFC3339Nano))

				// For --unique tracking (without timestamp)
				uniqueKey := fmt.Sprintf("%s:%d->%s:%d:%s:%d:%s",
					entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort,
					entry.Proto, entry.Pid, entry.Comm)

				// Determine if we should include this entry
				shouldInclude := false

				if uniqueOutput != nil && *uniqueOutput {
					// When using --unique, filter by the connection pattern without timestamp
					if !seenEntries[uniqueKey] {
						seenEntries[uniqueKey] = true
						seenEntries[timeKey] = true
						shouldInclude = true
					}
				} else {
					// Normal mode, filter only exact duplicates with timestamp
					if !seenEntries[timeKey] {
						seenEntries[timeKey] = true
						shouldInclude = true
					}
				}

				if shouldInclude {
					newEntries = append(newEntries, entry)
				}
			}

			// Skip if no new entries
			if len(newEntries) == 0 {
				continue
			}

			// Format output
			var output string
			if plainOutput != nil && *plainOutput {
				output = outputPlain(newEntries)
			} else {
				output = outputJSON(newEntries)
			}

			// Add newline if needed
			if output != "" && !strings.HasSuffix(output, "\n") {
				output += "\n"
			}

			// Write output to stdout
			fmt.Print(output)

		case <-ctx.Done():
			return
		}
	}
}

// startKProbes attaches a series of eBPF programs to kernel functions using KProbes.
//
// This function iterates over a slice of kprobeHook structs, each containing a kernel function
// name (kprobe) and an associated eBPF program. It attempts to attach each eBPF program to its
// respective kernel function using KProbes. If a Kprobe cannot be attached, an error message
// is logged, but the function continues with the next Kprobe.
//
// The function first checks if KProbes are supported by the current kernel. If not supported,
// it logs a fatal error and terminates the program.
//
// Parameters:
//
//	hooks []kprobeHook: A slice of kprobeHook structs, where each struct contains a kernel
//	function name and an associated eBPF program.
//
//	links []link.Link: A slice of link.Link objects to which successfully attached KProbes
//	are appended.
//
// Returns:
//
//	[]link.Link: The updated slice of link.Link objects, including any newly attached KProbes.
func startKProbes(hooks []kprobeHook, links []link.Link) []link.Link {
	var l link.Link

	err := features.HaveProgramType(ebpf.Kprobe)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Fatalf("KProbes are not supported on this kernel")
	}

	if err != nil {
		log.Fatalf("Error checking KProbes support: %v", err)
	}

	for _, kp := range hooks {
		l, err = link.Kprobe(kp.kprobe, kp.prog, nil)
		if err != nil {
			log.Printf("Unable to attach %q KProbe: %v", kp.kprobe, err)

			continue
		}

		links = append(links, l)
	}

	log.Printf("Using KProbes mode w/ PID/comm tracking")

	return links
}

// detectDNSServices tries to identify DNS services in the Kubernetes cluster
func detectDNSServices() {
	// If we have Kubernetes client initialized, we can try to detect DNS services
	if kubeClient != nil {
		ips, err := getDNSServiceIPs()
		if err != nil {
			log.Printf("Error detecting DNS services: %v", err)
		} else if len(ips) > 0 {
			dnsServiceIPs = ips
			log.Printf("Detected DNS service IPs: %v", dnsServiceIPs)
		}
	}

	if len(dnsServiceIPs) == 0 {
		log.Printf("Warning: No DNS service IPs detected, will not track internal DNS queries")
	}
}

// getDNSServiceIPs returns IPs of services listening on UDP port 53
func getDNSServiceIPs() ([]string, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("Kubernetes client not initialized")
	}

	var ips []string

	// Implementation will depend on the k8s client library being used
	// This is a simplified approach

	// Query services in all namespaces
	services, err := kubeClient.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %v", err)
	}

	// Look for services with port 53
	for _, svc := range services.Items {
		for _, port := range svc.Spec.Ports {
			if port.Port == 53 && (port.Protocol == "UDP" || port.Protocol == "") {
				if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
					ips = append(ips, svc.Spec.ClusterIP)
					log.Printf("Found DNS service: %s/%s at %s, will track internal DNS queries", svc.Namespace, svc.Name, svc.Spec.ClusterIP)
				}
			}
		}
	}

	return ips, nil
}

// isDNSServiceIP checks if the given IP is a known DNS service IP
func isDNSServiceIP(ip string) bool {
	for _, dnsIP := range dnsServiceIPs {
		if ip == dnsIP {
			return true
		}
	}
	return false
}

// trackDNSQueries processes entries to track DNS queries and their origins
func trackDNSQueries(entries []statEntry) {
	dnsRequestsMutex.Lock()
	defer dnsRequestsMutex.Unlock()

	for _, entry := range entries {
		// Check if this is a DNS query (UDP to port 53)
		if entry.Proto == "UDP" && entry.DstPort == 53 {
			// This is likely a DNS query, store the origin
			key := fmt.Sprintf("%s:%d-%s:%d", entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort)
			dnsRequestOrigins[key] = &dnsOrigin{
				SrcIP:     entry.SrcIP.String(),
				SrcPort:   entry.SrcPort,
				Pid:       uint32(entry.Pid),
				Comm:      entry.Comm,
				Timestamp: entry.Timestamp,
				PodName:   entry.SourcePod,
			}

			// Log for debugging
			log.Printf("Tracking DNS request from %s:%d (PID: %d, Comm: %s, Pod: %s) to %s:%d",
				entry.SrcIP, entry.SrcPort, entry.Pid, entry.Comm, entry.SourcePod, entry.DstIP, entry.DstPort)
		}
	}

	// Clean up old entries (older than 5 minutes)
	now := time.Now()
	for key, origin := range dnsRequestOrigins {
		if now.Sub(origin.Timestamp) > 5*time.Minute {
			delete(dnsRequestOrigins, key)
		}
	}
}

// enrichWithDNSOrigins adds DNS origin information to statEntry objects
func enrichWithDNSOrigins(entries []statEntry) {
	dnsRequestsMutex.RLock()
	defer dnsRequestsMutex.RUnlock()

	for i := range entries {
		// Skip entries that already have command, PID information
		if entries[i].Pid != 0 && entries[i].Comm != "" {
			continue
		}

		// Skip if not to/from a DNS service
		dstIsDNS := isDNSServiceIP(entries[i].DstIP.String())
		srcIsDNS := isDNSServiceIP(entries[i].SrcIP.String())

		if !dstIsDNS && !srcIsDNS {
			continue
		}

		// If this is a packet FROM a DNS server (response), try to correlate with origin
		if srcIsDNS {
			for _, origin := range dnsRequestOrigins {
				// If we find a matching origin, enrich the entry
				if time.Since(origin.Timestamp) < 5*time.Minute {
					// Update the entry with the original requester info
					entries[i].DNSOriginPid = int32(origin.Pid)
					entries[i].DNSOriginComm = origin.Comm
					entries[i].DNSOriginPod = origin.PodName
					break
				}
			}
		}
	}
}

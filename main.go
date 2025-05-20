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

	// Store merged DNS entries
	mergedDNSEntries      = make(map[string]*mergedDNSEntry) // key: unique identifier, value: merged entry
	mergedDNSEntriesMutex = &sync.RWMutex{}

	// Track DNS lookups by process (Pid:Comm)
	// key: "pid:comm", value: domain name
	dnsLookups      = make(map[string]string)
	dnsLookupsMutex = &sync.RWMutex{}

	// Store the eBPF objects for use in other functions
	globalObjs counterObjects
)

// dnsOrigin stores information about the original process that initiated a DNS request
type dnsOrigin struct {
	SrcIP     string
	SrcPort   uint16
	Pid       uint32
	Comm      string
	Timestamp time.Time
	PodName   string
	QueryName string // The domain name being queried
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

	// Store in global variable for use in other functions
	globalObjs = objs

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

	// Add a separate function to monitor DNS hostname resolution
	go monitorDNSResolution()

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

			// Create merged DNS entries automatically when in Kubernetes environment with detected DNS services
			var mergedOutput []mergedDNSEntry
			if kubeconfig != nil && *kubeconfig != "" && kubeClient != nil && len(dnsServiceIPs) > 0 {
				// We're in a Kubernetes environment with detected DNS services
				// Automatically merge DNS queries
				log.Printf("DNS services detected, will attempt to merge DNS queries")
				mergedDNSEntries := analyzeDNSQueries(entries)

				// Filter merged DNS entries for uniqueness if requested
				if uniqueOutput != nil && *uniqueOutput {
					seenMergedKeys := make(map[string]bool)
					for _, entry := range mergedDNSEntries {
						key := fmt.Sprintf("%s:%d->%s->%s:%d",
							entry.OriginalSrcIP, entry.OriginalSrcPort,
							entry.DNSServerIP,
							entry.ExternalDstIP, entry.ExternalDstPort)

						if !seenMergedKeys[key] {
							seenMergedKeys[key] = true
							mergedOutput = append(mergedOutput, entry)
						}
					}
				} else {
					mergedOutput = mergedDNSEntries
				}
			} else if kubeconfig != nil && *kubeconfig != "" && len(dnsServiceIPs) == 0 {
				log.Printf("No DNS services detected, skipping DNS query merging")
			}

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
			if len(newEntries) == 0 && len(mergedOutput) == 0 {
				continue
			}

			// Format output
			var output string
			if plainOutput != nil && *plainOutput {
				// Plain text output for normal entries
				regularOutput := outputPlain(newEntries)

				// Plain text output for merged DNS entries
				mergedDNSOut := outputMergedDNSPlain(mergedOutput)
				// Combine outputs without a separator
				output = regularOutput + mergedDNSOut
			} else {
				// JSON Lines format - output both normal entries and merged DNS entries
				regularOutput := outputJSONL(newEntries)
				mergedDNSOut := outputMergedDNSJSONL(mergedOutput)

				output = regularOutput
				if mergedDNSOut != "" {
					if output != "" {
						output += "\n"
					}
					output += mergedDNSOut
				}
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
	// If we have Kubernetes client initialized, try to detect DNS services
	if kubeClient != nil {
		ips, err := getDNSServiceIPs()
		if err != nil {
			log.Printf("Error detecting DNS services: %v", err)
		} else if len(ips) > 0 {
			dnsServiceIPs = ips
			log.Printf("Detected DNS service IPs: %v", dnsServiceIPs)
		}
	}

	// If we couldn't detect DNS services via the API, just warn
	if len(dnsServiceIPs) == 0 {
		log.Printf("Warning: No DNS service IPs detected via Kubernetes API, DNS tracking will be disabled")
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
			// Accept both TCP and UDP DNS services, or services without explicit protocol
			if port.Port == 53 && (port.Protocol == "UDP" || port.Protocol == "TCP" || port.Protocol == "") {
				if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
					ips = append(ips, svc.Spec.ClusterIP)
					log.Printf("Found DNS service: %s/%s at %s (protocol: %s), will track internal DNS queries",
						svc.Namespace, svc.Name, svc.Spec.ClusterIP, port.Protocol)
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

	// Access the DNS lookup data (protected by its own mutex)
	dnsLookupsMutex.RLock()
	defer dnsLookupsMutex.RUnlock()

	for _, entry := range entries {
		// Check if this is a DNS query (TCP or UDP to port 53)
		if (entry.Proto == "TCP" || entry.Proto == "UDP") && entry.DstPort == 53 {
			// Generate the key for this DNS request
			key := fmt.Sprintf("%s:%d-%s:%d", entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort)

			// Try multiple approaches to find the hostname for this query
			var hostname string

			// Approach 1: Look for direct IP:port-IP:port mapping (from tcpdump-style capture)
			if lookupKey := fmt.Sprintf("%s:%d-%s:53", entry.SrcIP, entry.SrcPort, entry.DstIP); dnsLookups[lookupKey] != "" {
				hostname = dnsLookups[lookupKey]
				log.Printf("Found hostname %s for DNS query %s (via direct mapping)", hostname, key)
			}

			// Approach 2: Look for PID:comm mapping (from uprobes)
			if hostname == "" && entry.Pid != 0 {
				pidCommKey := fmt.Sprintf("%d:%s", entry.Pid, entry.Comm)
				if dnsLookups[pidCommKey] != "" {
					hostname = dnsLookups[pidCommKey]
					log.Printf("Found hostname %s for DNS query %s (via PID/comm mapping)", hostname, key)
				}
			}

			// Store the DNS origin
			dnsRequestOrigins[key] = &dnsOrigin{
				SrcIP:     entry.SrcIP.String(),
				SrcPort:   entry.SrcPort,
				Pid:       uint32(entry.Pid),
				Comm:      entry.Comm,
				Timestamp: entry.Timestamp,
				PodName:   entry.SourcePod,
				QueryName: hostname,
			}

			// Log for debugging
			if hostname != "" {
				log.Printf("Tracking DNS request from %s:%d (PID: %d, Comm: %s, Pod: %s) to %s:%d for %s",
					entry.SrcIP, entry.SrcPort, entry.Pid, entry.Comm, entry.SourcePod, entry.DstIP, entry.DstPort, hostname)
			} else {
				log.Printf("Tracking DNS request from %s:%d (PID: %d, Comm: %s, Pod: %s) to %s:%d",
					entry.SrcIP, entry.SrcPort, entry.Pid, entry.Comm, entry.SourcePod, entry.DstIP, entry.DstPort)
			}
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
			// Look for the most recent matching origin
			var bestOrigin *dnsOrigin
			var newestTimestamp time.Time

			for _, origin := range dnsRequestOrigins {
				// Only consider recent entries (within the last 5 minutes)
				if time.Since(origin.Timestamp) < 5*time.Minute {
					// Choose the most recent origin as the best match
					if bestOrigin == nil || origin.Timestamp.After(newestTimestamp) {
						bestOrigin = origin
						newestTimestamp = origin.Timestamp
					}
				}
			}

			// If we found a matching origin, enrich the entry
			if bestOrigin != nil {
				entries[i].DNSOriginPid = int32(bestOrigin.Pid)
				entries[i].DNSOriginComm = bestOrigin.Comm
				entries[i].DNSOriginPod = bestOrigin.PodName

				log.Printf("Enriched entry from DNS server %s with origin information: pod=%s, comm=%s, pid=%d",
					entries[i].SrcIP.String(), bestOrigin.PodName, bestOrigin.Comm, bestOrigin.Pid)
			}
		}
	}
}

// analyzeDNSQueries looks for patterns of internal→DNS→external queries and merges related entries
func analyzeDNSQueries(entries []statEntry) []mergedDNSEntry {
	// First pass: identify DNS server queries (from internal pods to DNS service)
	// and external DNS queries (from DNS service to external resolvers)
	var internalQueries, externalQueries []statEntry

	for _, entry := range entries {
		dstIPStr := entry.DstIP.String()
		srcIPStr := entry.SrcIP.String()

		// Check if this query is to a DNS server (internal query)
		isDNSServer := false
		for _, dnsIP := range dnsServiceIPs {
			if dstIPStr == dnsIP {
				isDNSServer = true
				break
			}
		}

		// Check if this query is from a DNS server (external query)
		isFromDNSServer := false
		for _, dnsIP := range dnsServiceIPs {
			if srcIPStr == dnsIP {
				isFromDNSServer = true
				break
			}
		}

		// If the query is to a DNS server and the destination port is 53, it's an internal query
		if isDNSServer && entry.DstPort == 53 {
			log.Printf("Detected internal DNS query: %s:%d -> %s:%d (proto: %s, comm: %s, pod: %s)",
				entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort,
				entry.Proto, entry.Comm, entry.SourcePod)
			internalQueries = append(internalQueries, entry)
		} else if isFromDNSServer && entry.DstPort == 53 {
			// If the query is from a DNS server to an external IP and the destination port is 53, it's an external query
			log.Printf("Detected external DNS query: %s:%d -> %s:%d (proto: %s, comm: %s)",
				entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort,
				entry.Proto, entry.Comm)
			externalQueries = append(externalQueries, entry)
		}
	}

	// Now correlate internal and external queries
	mergedDNSEntriesMutex.Lock()
	defer mergedDNSEntriesMutex.Unlock()

	// Process all internal queries first
	for _, internalQuery := range internalQueries {
		// Generate a key that will help us track this request
		clientKey := fmt.Sprintf("%s:%d", internalQuery.SrcIP.String(), internalQuery.SrcPort)

		// Look for DNS hostname information in our dnsRequestOrigins
		var queryName string
		dnsRequestsMutex.RLock()
		for k, origin := range dnsRequestOrigins {
			// Check if this origin matches our internal query
			if strings.HasPrefix(k, fmt.Sprintf("%s:%d-", internalQuery.SrcIP.String(), internalQuery.SrcPort)) &&
				origin.QueryName != "" {
				queryName = origin.QueryName
				log.Printf("Found hostname %s for internal DNS query from %s:%d",
					queryName, internalQuery.SrcIP, internalQuery.SrcPort)
				break
			}
		}
		dnsRequestsMutex.RUnlock()

		// Create a new merged entry
		merged := &mergedDNSEntry{
			// Original client info (the pod making the request)
			OriginalSrcIP:   internalQuery.SrcIP.String(),
			OriginalSrcPort: internalQuery.SrcPort,
			OriginalPod:     internalQuery.SourcePod,
			OriginalComm:    internalQuery.Comm,
			OriginalPid:     internalQuery.Pid,
			Timestamp:       internalQuery.Timestamp,

			// DNS server info (this will be completed by the external query later)
			DNSServerIP:  internalQuery.DstIP.String(),
			DNSServerPod: internalQuery.DstPod,

			// Protocol info
			Proto:         internalQuery.Proto,
			LikelyService: internalQuery.LikelyService,

			// DNS query name if available
			QueryName: queryName,
		}

		// If we can get DNS server info from destination pod information
		// We can set it here, otherwise it will be set from external query
		if strings.Contains(internalQuery.DstPod, "coredns") {
			merged.DNSServerComm = "coredns"
		} else if strings.Contains(internalQuery.DstPod, "kube-dns") {
			merged.DNSServerComm = "kube-dns"
		}

		// Log with hostname if available
		if queryName != "" {
			log.Printf("Creating new merged DNS entry for: %s:%d (%s) -> DNS server: %s (%s) for hostname: %s",
				merged.OriginalSrcIP, merged.OriginalSrcPort, merged.OriginalPod,
				merged.DNSServerIP, merged.DNSServerPod, queryName)
		} else {
			log.Printf("Creating new merged DNS entry for: %s:%d (%s) -> DNS server: %s (%s)",
				merged.OriginalSrcIP, merged.OriginalSrcPort, merged.OriginalPod,
				merged.DNSServerIP, merged.DNSServerPod)
		}

		// Add to map of merged entries
		mergedDNSEntries[clientKey] = merged
	}

	// Now process external queries and try to match them
	for _, externalQuery := range externalQueries {
		// We need to match this external query with the internal query that caused it
		// Log the external query we're trying to match for debugging
		log.Printf("Trying to match external DNS query: %s -> %s:%d (PID: %d, comm: %s)",
			externalQuery.SrcIP, externalQuery.DstIP, externalQuery.DstPort,
			externalQuery.Pid, externalQuery.Comm)

		var bestMatch *mergedDNSEntry
		var bestKey string
		var bestScore int = -1 // Higher score = better match

		// External query is from DNS server to external resolver
		// Internal query is from pod to DNS server
		// The DNS server is the connector between them

		for key, merged := range mergedDNSEntries {
			// Skip entries that already have external info
			if merged.ExternalDstIP != "" {
				continue
			}

			score := 0

			// Check if the DNS server IP in the internal query matches the source IP of the external query
			if merged.DNSServerIP == externalQuery.SrcIP.String() {
				score += 5
				log.Printf("  DNS server IP match: %s", merged.DNSServerIP)
			}

			// Check time proximity (higher score for closer time)
			timeDiff := externalQuery.Timestamp.Sub(merged.Timestamp)
			if timeDiff >= 0 && timeDiff < 100*time.Millisecond {
				score += 4
				log.Printf("  Very close time match: %v", timeDiff)
			} else if timeDiff >= 0 && timeDiff < 500*time.Millisecond {
				score += 3
				log.Printf("  Close time match: %v", timeDiff)
			} else if timeDiff >= 0 && timeDiff < 2*time.Second {
				score += 2
				log.Printf("  Recent time match: %v", timeDiff)
			} else if timeDiff >= 0 && timeDiff < 5*time.Second {
				score += 1
				log.Printf("  Distant time match: %v", timeDiff)
			} else {
				continue // Too far apart in time, skip this entry
			}

			// Prefer matching DNS server's known name
			if externalQuery.Comm == "coredns" || strings.Contains(externalQuery.SourcePod, "coredns") {
				score += 3
				log.Printf("  CoreDNS process identified")
			} else if externalQuery.Comm == "kube-dns" || strings.Contains(externalQuery.SourcePod, "kube-dns") {
				score += 3
				log.Printf("  KubeDNS process identified")
			}

			// Protocols should match (TCP or UDP)
			if merged.Proto == externalQuery.Proto {
				score += 2
				log.Printf("  Protocol match: %s", merged.Proto)
			}

			// If we have a better score, update the best match
			if score > bestScore {
				bestScore = score
				bestMatch = merged
				bestKey = key
				log.Printf("  New best match with score %d", score)
			}
		}

		// If we found a match, update the merged entry with external info
		if bestMatch != nil && bestScore >= 3 { // Require a minimum score to consider a valid match
			log.Printf("Matched DNS query: %s:%d (%s) -> %s -> %s:%d (score: %d)",
				bestMatch.OriginalSrcIP, bestMatch.OriginalSrcPort, bestMatch.OriginalPod,
				externalQuery.SrcIP, externalQuery.DstIP, externalQuery.DstPort, bestScore)

			bestMatch.ExternalDstIP = externalQuery.DstIP.String()
			bestMatch.ExternalDstPort = externalQuery.DstPort

			// Take the DNS server comm/pid info from the external query
			// This is important because the external query is made by the DNS server
			bestMatch.DNSServerComm = externalQuery.Comm
			bestMatch.DNSServerPid = externalQuery.Pid

			// Update the entry in the map
			mergedDNSEntries[bestKey] = bestMatch
		} else {
			log.Printf("Could not match external DNS query to %s:%d with any internal query (best score: %d)",
				externalQuery.DstIP.String(), externalQuery.DstPort, bestScore)
		}
	}

	// Convert map to slice for return
	result := make([]mergedDNSEntry, 0, len(mergedDNSEntries))
	for _, entry := range mergedDNSEntries {
		// Only include entries that have both internal and external components
		if entry.ExternalDstIP != "" {
			result = append(result, *entry)
		}
	}

	return result
}

// kernelStringToGo converts a null-terminated C string from kernel space to a Go string
func kernelStringToGo(bytes []byte) string {
	for i, b := range bytes {
		if b == 0 {
			return string(bytes[:i])
		}
	}
	return string(bytes)
}

// DNSQueryInfo represents the format of entries in the dns_queries map
type DNSQueryInfo struct {
	Hostname [80]byte
	Pid      uint32
	Comm     [16]byte
}

// monitorDNSResolution uses eBPF uprobes to capture DNS resolution calls
func monitorDNSResolution() {
	log.Printf("Starting DNS resolution monitoring with eBPF uprobes")

	// Libraries that may contain DNS resolution functions
	libraries := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",     // Standard C library
		"/lib64/libc.so.6",                    // Alternative path
		"/usr/lib/x86_64-linux-gnu/libc.so.6", // Another alternative path
		"/usr/lib64/libc.so.6",                // Another alternative path
	}

	var libPath string
	for _, lib := range libraries {
		if _, err := os.Stat(lib); err == nil {
			libPath = lib
			break
		}
	}

	if libPath == "" {
		log.Printf("Could not find libc library, DNS hostname resolution will not be available")
		return
	}

	log.Printf("Using libc library at %s for DNS resolution tracking", libPath)

	// Store our uprobe links
	var dnsLinks []link.Link
	defer func() {
		for _, l := range dnsLinks {
			_ = l.Close()
		}
	}()
	// We can now directly access the programs from the global objects
	// Define variables in the scope where they're needed

	// Attempt to attach user-space probes if the required objects are available
	// These objects will only be available if the eBPF code has been compiled
	// with the new user space probes

	// Check if programs are available
	hasGetaddrinfo := globalObjs.GetaddrinfoEntry != nil
	hasGethostbyname := globalObjs.GethostbynameEntry != nil
	hasGethostbyname2 := globalObjs.Gethostbyname2Entry != nil

	if !hasGetaddrinfo && !hasGethostbyname && !hasGethostbyname2 {
		log.Printf("DNS resolution programs are not available in the compiled eBPF code")
		log.Printf("Rebuild the project for full DNS resolution support")
	} else {
		log.Printf("DNS resolution programs found in the eBPF code")

		// Open the library as an executable
		ex, err := link.OpenExecutable(libPath)
		if err != nil {
			log.Printf("Failed to open library as executable: %v", err)
		} else {
			// Create attachments for all available programs
			if hasGetaddrinfo {
				l, err := ex.Uprobe("getaddrinfo", globalObjs.GetaddrinfoEntry, nil)
				if err != nil {
					log.Printf("Failed to attach uprobe for getaddrinfo: %v", err)
				} else {
					dnsLinks = append(dnsLinks, l)
					log.Printf("Successfully attached uprobe for getaddrinfo")
				}
			}

			if hasGethostbyname {
				l, err := ex.Uprobe("gethostbyname", globalObjs.GethostbynameEntry, nil)
				if err != nil {
					log.Printf("Failed to attach uprobe for gethostbyname: %v", err)
				} else {
					dnsLinks = append(dnsLinks, l)
					log.Printf("Successfully attached uprobe for gethostbyname")
				}
			}

			if hasGethostbyname2 {
				l, err := ex.Uprobe("gethostbyname2", globalObjs.Gethostbyname2Entry, nil)
				if err != nil {
					log.Printf("Failed to attach uprobe for gethostbyname2: %v", err)
				} else {
					dnsLinks = append(dnsLinks, l)
					log.Printf("Successfully attached uprobe for gethostbyname2")
				}
			}
		}
	}

	if len(dnsLinks) == 0 {
		log.Printf("No DNS resolution probes could be attached")
	}

	// Create a ticker to periodically check for DNS resolutions
	ticker := time.NewTicker(500 * time.Millisecond)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			if globalObjs.DnsQueries != nil {
				// Use the helper function to read from the DNS queries map
				readDNSQueriesMap(globalObjs.DnsQueries)
			} else {
				// Fall back to basic packet analysis
				updateDNSLookups()
			}
		}
	}()
}

// updateDNSLookups analyzes packet data to identify DNS queries
func updateDNSLookups() {
	// Without the dns_queries map, we'll try to derive DNS information from network packets
	// This is a simplified approach that will be enhanced when the eBPF program is updated

	dnsLookupsMutex.Lock()
	defer dnsLookupsMutex.Unlock()

	// Just logging that we're checking - actual implementation will be much more robust
	// with the dns_queries map from the eBPF program
	log.Printf("Analyzing packet data for DNS queries (limited capability until rebuild)")

	// Clean up old entries (older than 5 minutes)
	now := time.Now()
	for key, ts := range dnsLookupTimestamps {
		if now.Sub(ts) > 5*time.Minute {
			delete(dnsLookups, key)
			delete(dnsLookupTimestamps, key)
		}
	}
}

// Track when DNS lookups were added so we can clean them up
var dnsLookupTimestamps = make(map[string]time.Time)

//go:build linux
// +build linux

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
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

	// DNS hostnames to IP mappings
	dnsHostToIP    = make(map[string][]dnsMapping) // key: hostname, value: slice of IPs
	dnsIPToHost    = make(map[string][]dnsMapping) // key: IP string, value: slice of hostnames
	dnsHostIPMutex = &sync.RWMutex{}
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

// processDNSEvent converts a DNS lookup event from eBPF to Go format
func processDNSEvent(event dnsLookupEvent) {
	// Extract hostname (null-terminated C string)
	hostname := convertCStringToGo(event.Host[:])
	log.Printf("Processing DNS event with host: %s, PID: %d", hostname, event.Pid)

	if hostname == "" {
		log.Printf("Empty hostname in DNS event, skipping")
		return
	}

	// Get process command
	comm := convertCStringToGo(event.Comm[:])
	log.Printf("DNS event command: %s", comm)

	// Create IP address
	var ip netip.Addr
	var ok bool
	if event.AddrType == syscall.AF_INET {
		// IPv4
		log.Printf("Processing IPv4 address from DNS event")
		ip, ok = netip.AddrFromSlice(event.IP[:4])
	} else if event.AddrType == syscall.AF_INET6 {
		// IPv6
		log.Printf("Processing IPv6 address from DNS event")
		ip, ok = netip.AddrFromSlice(event.IP[:])
	} else {
		log.Printf("Unknown address type in DNS event: %d", event.AddrType)
		return // Unsupported address type
	}

	if !ok {
		log.Printf("Error converting IP address in DNS event")
		return
	}

	log.Printf("Successfully processed DNS event: %s -> %s (PID: %d, Comm: %s)",
		hostname, ip.String(), event.Pid, comm)

	// Create a new DNS mapping
	mapping := dnsMapping{
		Hostname:    hostname,
		IP:          ip,
		Pid:         event.Pid,
		Comm:        comm,
		Timestamp:   time.Now(),
		AddressType: event.AddrType,
	}

	// If we have K8s, try to find the pod name
	if kubeClient != nil {
		mapping.PodName = lookupPodForIP(ip)
	}

	// Update our DNS maps
	dnsHostIPMutex.Lock()
	defer dnsHostIPMutex.Unlock()

	// Add to hostname->IP map
	dnsHostToIP[hostname] = append(dnsHostToIP[hostname], mapping)

	// Add to IP->hostname map
	ipStr := ip.String()
	dnsIPToHost[ipStr] = append(dnsIPToHost[ipStr], mapping)

	// Log the DNS resolution
	log.Printf("DNS resolved: %s -> %s (PID: %d, Comm: %s, Pod: %s)",
		hostname, ipStr, event.Pid, comm, mapping.PodName)
}

// Read DNS events from the ringbuffer
func processDNSEvents(ctx context.Context, reader *ringbuf.Reader) {
	var event dnsLookupEvent

	log.Printf("Starting DNS events processing goroutine")
	eventCount := 0

	for {
		// Check if context is done before blocking on Read
		select {
		case <-ctx.Done():
			log.Printf("DNS event reader context done, exiting after processing %d events", eventCount)
			return
		default:
			// Continue with read operation
		}

		// Set up a timeout channel
		readDone := make(chan struct{})
		var record ringbuf.Record
		var readErr error

		// Start read in a goroutine
		go func() {
			record, readErr = reader.Read()
			close(readDone)
		}()

		// Wait for either read completion or timeout
		select {
		case <-readDone:
			// Handle the read result
			if readErr != nil {
				if errors.Is(readErr, ringbuf.ErrClosed) {
					log.Printf("DNS ring buffer closed, exiting after processing %d events", eventCount)
					return
				}
				log.Printf("Error reading DNS event: %v", readErr)
				continue
			}

			log.Printf("Received data from ring buffer, size: %d bytes", len(record.RawSample))

			// Safely parse the event with bounds checking
			expectedSize := int(unsafe.Sizeof(event))
			if len(record.RawSample) != expectedSize {
				log.Printf("Invalid DNS event size: got %d, expected %d - trying to process anyway",
					len(record.RawSample), expectedSize)

				// Still try to copy what we can
				copySize := len(record.RawSample)
				if copySize > expectedSize {
					copySize = expectedSize
				}

				// Clear event struct before partial copy
				event = dnsLookupEvent{}
				copy((*[unsafe.Sizeof(event)]byte)(unsafe.Pointer(&event))[:copySize], record.RawSample[:copySize])
			} else {
				// Standard case - sizes match
				copy((*[unsafe.Sizeof(event)]byte)(unsafe.Pointer(&event))[:], record.RawSample)
			}

			// Process the event and count it
			processDNSEvent(event)
			eventCount++

		case <-time.After(1 * time.Second):
			// Just log and continue if we timeout
			log.Printf("DNS ring buffer read timed out, retrying (events so far: %d)", eventCount)

		case <-ctx.Done():
			log.Printf("DNS event reader context done during read, exiting after processing %d events", eventCount)
			return
		}
	}
}

// Convert a C-style null-terminated string to Go string
func convertCStringToGo(cString []byte) string {
	// Find null terminator
	length := 0
	for ; length < len(cString); length++ {
		if cString[length] == 0 {
			break
		}
	}
	return string(cString[:length])
}

// Enhanced version of enrichWithDNSOrigins that also uses the DNS hostname mapping
func enrichWithDNSInfo(entries []statEntry) {
	// Just use the existing DNS origin enrichment for now
	enrichWithDNSOrigins(entries)
}

// Cleanup old DNS mappings periodically
func cleanupDNSMappings() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cleanupTime := time.Now().Add(-30 * time.Minute)

		dnsHostIPMutex.Lock()

		// Clean hostname->IP map
		for hostname, mappings := range dnsHostToIP {
			var newMappings []dnsMapping
			for _, mapping := range mappings {
				if mapping.Timestamp.After(cleanupTime) {
					newMappings = append(newMappings, mapping)
				}
			}

			if len(newMappings) == 0 {
				delete(dnsHostToIP, hostname)
			} else {
				dnsHostToIP[hostname] = newMappings
			}
		}

		// Clean IP->hostname map
		for ip, mappings := range dnsIPToHost {
			var newMappings []dnsMapping
			for _, mapping := range mappings {
				if mapping.Timestamp.After(cleanupTime) {
					newMappings = append(newMappings, mapping)
				}
			}

			if len(newMappings) == 0 {
				delete(dnsIPToHost, ip)
			} else {
				dnsIPToHost[ip] = newMappings
			}
		}

		dnsHostIPMutex.Unlock()
	}
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

	// Set up kprobes for packet tracking
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

	// Set up uprobes for DNS tracking
	// Try multiple potential libc locations
	libcLocations := []string{
		"/lib64/libc.so.6",                // Common on some systems
		"/lib/x86_64-linux-gnu/libc.so.6", // Debian/Ubuntu
		"/usr/lib/libc.so.6",              // Potential fallback
		"/usr/lib64/libc.so.6",            // Another potential location
	}

	var libcLocation string
	var libcExists bool

	for _, loc := range libcLocations {
		if _, err := os.Stat(loc); err == nil {
			libcLocation = loc
			libcExists = true
			log.Printf("Found libc at: %s", libcLocation)
			break
		}
	}

	if !libcExists {
		log.Printf("WARNING: Could not find libc.so.6 in any standard locations, using default")
		libcLocation = "/lib64/libc.so.6" // Default fallback
	}

	upHooks := []uprobeHook{
		{
			library:   libcLocation,
			symbol:    "getaddrinfo",
			prog:      objs.UprobeGetaddrinfo,
			probeType: "uprobe",
			isReturn:  false,
		},
		{
			library:   libcLocation,
			symbol:    "getaddrinfo",
			prog:      objs.UretprobeGetaddrinfo,
			probeType: "uretprobe",
			isReturn:  true,
		},
		{
			library:   libcLocation,
			symbol:    "gethostbyname",
			prog:      objs.UretprobeGethostbyname,
			probeType: "uretprobe",
			isReturn:  true,
		},
		// Add additional probes for variants that might be used
		{
			library:   libcLocation,
			symbol:    "gethostbyname2",
			prog:      objs.UretprobeGethostbyname, // Reuse the same BPF program
			probeType: "uretprobe",
			isReturn:  true,
		},
		{
			library:   libcLocation,
			symbol:    "gethostbyname_r",
			prog:      objs.UretprobeGethostbyname, // Reuse the same BPF program
			probeType: "uretprobe",
			isReturn:  true,
		},
		{
			library:   libcLocation,
			symbol:    "gethostbyname2_r",
			prog:      objs.UretprobeGethostbyname, // Reuse the same BPF program
			probeType: "uretprobe",
			isReturn:  true,
		},
	}

	// Open the executable once outside the loop
	ex, err := link.OpenExecutable(libcLocation)
	if err != nil {
		log.Fatalf("Failed to open executable: %v", err)
	}

	for _, up := range upHooks {
		log.Printf("Attaching %s to %s", up.probeType, up.symbol)

		var l link.Link
		if up.probeType == "uprobe" {
			l, err = ex.Uprobe(up.symbol, up.prog, nil)
		} else {
			l, err = ex.Uretprobe(up.symbol, up.prog, nil)
		}
		if err != nil {
			log.Fatalf("Failed to attach uprobe: %v", err)
		}

		links = append(links, l)
		log.Printf("Successfully attached %s to %s", up.probeType, up.symbol)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a goroutine to process DNS events from the ringbuffer
	dnsReader, err := ringbuf.NewReader(objs.DnsEvents)
	if err != nil {
		log.Printf("Failed to create ringbuf reader for DNS events: %v", err)
	} else {
		log.Printf("Created DNS events ringbuf reader successfully")
		go processDNSEvents(ctx, dnsReader)
		defer dnsReader.Close()
	}

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
			log.Printf("Ticker fired, processing map...")
			// Process the map
			entries, err := processMap(objs.PktCount, timeDateSort)
			if err != nil {
				log.Printf("Error reading eBPF map: %v", err)
				continue
			}

			log.Printf("Found %d entries in map", len(entries))

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

			// For debugging purposes, also log if this is a DNS response
		} else if entry.Proto == "UDP" && entry.SrcPort == 53 {
			log.Printf("Detected DNS response from %s:%d to %s:%d",
				entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort)
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

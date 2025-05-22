package main

import (
	"context"
	"fmt"
	"log"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
		if (entry.Proto == "UDP" || entry.Proto == "TCP") && entry.DstPort == 53 {
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
		} else if (entry.Proto == "UDP" || entry.Proto == "TCP") && entry.SrcPort == 53 {
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

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

func processDNSEvents(ctx context.Context, reader *ringbuf.Reader) error {
	perfChan := make(chan []byte, 0)

	go func(perfChan chan []byte, reader *ringbuf.Reader) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := reader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("Error reading DNS event: %v", err)
					continue
				}
				perfChan <- record.RawSample
			}
		}
	}(perfChan, reader)

	var event dnsLookupEvent

	for {
		select {
		case <-time.After(1 * time.Millisecond):
			continue
		case <-ctx.Done():
			log.Printf("Context done, exiting")
			return nil
		default:
			record, ok := <-perfChan
			if !ok {
				panic("perfChan closed")
			}
			err := binary.Read(bytes.NewReader(record), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Error reading DNS event: %v", err)
				continue
			}

			// Extract null-terminated strings
			hostname := nullTerminatedString(event.Host[:])
			commName := nullTerminatedString(event.Comm[:])

			// Create IP address string based on address type
			var ipStr string
			if event.AddrType == 0 {
				// This is a pre-resolution event (from uprobe/gethostbyname)
				log.Printf("DNS Lookup: Process %s (PID %d) looking up hostname: %s",
					commName, event.Pid, hostname)
			} else if event.AddrType == syscall.AF_INET {
				// IPv4 address
				ip := net.IPv4(event.IP[0], event.IP[1], event.IP[2], event.IP[3])
				ipStr = ip.String()
				log.Printf("DNS Resolution: Process %s (PID %d) resolved %s to IPv4: %s",
					commName, event.Pid, hostname, ipStr)
			} else if event.AddrType == syscall.AF_INET6 {
				// IPv6 address
				ip := net.IP(event.IP[:])
				ipStr = ip.String()
				log.Printf("DNS Resolution: Process %s (PID %d) resolved %s to IPv6: %s",
					commName, event.Pid, hostname, ipStr)
			}
		}
	}
}

// Helper function to extract null-terminated strings from byte arrays
func nullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

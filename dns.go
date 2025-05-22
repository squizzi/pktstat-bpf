package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
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

	var (
		event dnsLookupEvent
		ip    net.IP
	)

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

			// Convert C string to Go string
			hostname := string(event.Host[:bytes.IndexByte(event.Host[:], 0)])
			if event.AddrType == 2 {
				ip = net.IP(event.IP[:4])
			} else {
				ip = net.IP(event.IP[:])
			}

			log.Printf("DNS lookup: %s -> %s", hostname, ip)
		}
	}
}

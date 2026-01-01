package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	BPF_OBJECT_FILE_PATH string = "./xdp_anti_ddos.bpf.o"
	PROGRAM_NAME         string = "xdp_anti_ddos"
	BLOCKED_MAP_NAME     string = "blocked_ipv4"
	EVENTS_MAP_NAME      string = "events"
	STATS_MAP_NAME       string = "stats_map"

	REASON_BLOCKLIST    string = "blocklist"
	REASON_RATE_LIMITED string = "rate_limited"
)

type Stats struct {
	PktsTotal        uint64
	PktsIPv4         uint64
	PktsTCP          uint64
	PktsSYN          uint64
	DropBlocklist    uint64
	DropAutoblock    uint64
	AutoblockActions uint64
}

func ipToU32(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not IPv4: %v", ip)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func u32ToIP(u uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, u)
	return net.IP(b)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <iface>", os.Args[0])
	}
	ifaceName := os.Args[1]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interfaceByName: %v", err)
	}

	// Load the compiled BPF object file.
	spec, err := ebpf.LoadCollectionSpec(BPF_OBJECT_FILE_PATH)
	if err != nil {
		log.Fatalf("LoadCollectionSpec: %v", err)
	}

	// Create collection (maps + programs)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[PROGRAM_NAME]
	if prog == nil {
		log.Fatalf("program %s not found", PROGRAM_NAME)
	}

	blockedMap := coll.Maps[BLOCKED_MAP_NAME]
	if blockedMap == nil {
		log.Fatalf("map %s not found", BLOCKED_MAP_NAME)
	}

	eventsMap := coll.Maps[EVENTS_MAP_NAME]
	if eventsMap == nil {
		log.Fatalf("map %s not found", EVENTS_MAP_NAME)
	}

	statsMap := coll.Maps[STATS_MAP_NAME]
	if statsMap == nil {
		log.Fatalf("map %s not found", STATS_MAP_NAME)
	}

	// Attach XDP program.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("AttachXDP: %v", err)
	}
	defer xdpLink.Close()

	log.Printf("attached XDP program to %s (index=%d)", ifaceName, iface.Index)

	// Start ring buffer reader
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	go func() {
		time.Sleep(5 * time.Second)
		ip := net.ParseIP("88.88.88.88")
		u, err := ipToU32(ip)
		if err != nil {
			log.Printf("bad ip: %v", err)
			return
		}
		val := uint8(1)
		if err := blockedMap.Put(u, val); err != nil {
			log.Printf("blockedMap.Put: %v", err)
			return
		}
		log.Printf("blocked %s", ip.String())
	}()

	// Event loop
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("ringbuf read error: %v", err)
				continue
			}

			// Event decoding in a safe way, manually.
			raw := record.RawSample
			if len(raw) != 16 {
				log.Printf("bad event size: %d", len(raw))
				continue
			}
			ts := binary.LittleEndian.Uint64(raw[0:8])
			srcIPHost := binary.LittleEndian.Uint32(raw[8:12])
			dstPort := binary.LittleEndian.Uint16(raw[12:14])
			reasonCode := raw[14]
			flags := raw[15]

			ipBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(ipBytes, srcIPHost)
			srcIP := net.IP(ipBytes)

			var reason string
			switch reasonCode {
			case 1:
				reason = REASON_BLOCKLIST
			case 3:
				reason = REASON_RATE_LIMITED
			default:
				reason = "unknown"
			}

			log.Printf("DROP src=%s dstPort=%d reason=%s flags=0x%x ts=%d",
				srcIP.String(), dstPort, reason, flags, ts)
		}
	}()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var prev Stats

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// PERCPU_ARRAY has a single key (0)
				var key uint32 = 0
				var perCPU []Stats
				if err := statsMap.Lookup(key, &perCPU); err != nil {
					log.Printf("statsMap.Lookup: %v", err)
					continue
				}

				// Sum across CPUs
				var cur Stats
				for _, s := range perCPU {
					cur.PktsTotal += s.PktsTotal
					cur.PktsIPv4 += s.PktsIPv4
					cur.PktsTCP += s.PktsTCP
					cur.PktsSYN += s.PktsSYN
					cur.DropBlocklist += s.DropBlocklist
					cur.DropAutoblock += s.DropAutoblock
					cur.AutoblockActions += s.AutoblockActions
				}

				// Compute deltas per second
				dTotal := cur.PktsTotal - prev.PktsTotal
				dSyn := cur.PktsSYN - prev.PktsSYN
				dDropBL := cur.DropBlocklist - prev.DropBlocklist
				dDropAB := cur.DropAutoblock - prev.DropAutoblock

				log.Printf("pps=%d syn/s=%d dropBL/s=%d dropAB/s=%d autoblocks=%d",
					dTotal, dSyn, dDropBL, dDropAB, cur.AutoblockActions)

				prev = cur
			}
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down")
}

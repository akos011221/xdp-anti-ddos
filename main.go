package main

import (
	"bytes"
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
	bpfObjectFilePath string = "./bpf/xdp_anti_ddos.bpf.o"
	programName       string = "xdp_anti_ddos"
	blockedMapName    string = "blocked_ipv4"
	eventsMapName     string = "events"
)

type DropEvent struct {
	TsNs     uint64
	ScrIP    uint32
	DstPort  uint16
	Reason   uint8
	TcpFlags uint8
	_        uint16 // Padding.
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
	spec, err := ebpf.LoadCollectionSpec(bpfObjectFilePath)
	if err != nil {
		log.Fatalf("LoadCollectionSpec: %v", err)
	}

	// Create collection (maps + programs)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[programName]
	if prog == nil {
		log.Fatalf("program %s not found", programName)
	}

	blockedMap := coll.Maps[blockedMapName]
	if blockedMap == nil {
		log.Fatalf("map %s not found", blockedMapName)
	}

	eventsMap := coll.Maps[eventsMapName]
	if eventsMap == nil {
		log.Fatalf("map %s not found", eventsMapName)
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

			var e DropEvent
			// ringbuf payload is raw bytes.
			// In BPF, the struct fields are stored in native endianess of the CPU.
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decode event: %v", err)
				continue
			}

			srcIP := make(net.IP, 4)
			binary.BigEndian.PutUint32(srcIP, e.ScrIP)

			log.Printf("DROP src=%s dstPort=%d reason=%d flags=0x%x ts=%d",
				srcIP.String(), e.DstPort, e.Reason, e.TcpFlags, e.TsNs)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down")
}

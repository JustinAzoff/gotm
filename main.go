package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type trackedFlow struct {
	count int
	last  time.Time
}

func (t trackedFlow) String() string {
	return fmt.Sprintf("packets=%d last=%s", t.count, t.last)
}

func handlePacket(p gopacket.Packet) string {
	src, dst := p.NetworkLayer().NetworkFlow().Endpoints()
	var sport, dport gopacket.Endpoint
	tl := p.TransportLayer()
	if tl != nil {
		sport, dport = tl.TransportFlow().Endpoints()
	}
	return fmt.Sprintf("%s:%s %s:%s", src, sport, dst, dport)
}

func main() {
	var err error
	intf := os.Args[1]
	handle, err := pcap.OpenLive(intf, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter("(ip or ip6) and not host 192.168.2.230")
	if err != nil { // optional
		panic(err)
	}

	outf, err := os.Create("out.pcap")
	pcapWriter := pcapgo.NewWriter(outf)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.

	seen := make(map[string]*trackedFlow)
	totalPackets := 0
	outputPackets := 0
	lastcleanup := time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		totalPackets += 1
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}
		flow := handlePacket(packet) // Do something with each packet.
		flw := seen[flow]
		if flw == nil {
			flw = &trackedFlow{
				count: 1,
				last:  time.Now(),
			}
			seen[flow] = flw
			log.Println("NEW", flw, flow)
		} else {
			flw.count += 1
			flw.last = time.Now()
		}
		if flw.count < 100 {
			//log.Println(flow, flw, "continues")
			outputPackets += 1
			err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Fatal("Error writing output pcap", err)
			}
		}
		//Cleanup
		if totalPackets%100 == 0 && time.Since(lastcleanup) > time.Second {
			lastcleanup = time.Now()
			var remove []string
			for flow, flw := range seen {
				if lastcleanup.Sub(flw.last) > 5*time.Second {
					log.Println("TO ", flw, flow)
					remove = append(remove, flow)
				}
			}
			for _, rem := range remove {
				delete(seen, rem)
			}
			log.Printf("Tracking %d connections. total packets seen %d. total packets output %d", len(seen), totalPackets, outputPackets)
			log.Println()
		}
	}
}

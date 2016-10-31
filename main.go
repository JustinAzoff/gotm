package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var packetCountInterval = 5000
var packetTimeInterval = 5 * time.Second

type trackedFlow struct {
	count int
	last  time.Time
}

func (t trackedFlow) String() string {
	return fmt.Sprintf("packets=%d last=%s", t.count, t.last)
}

func handlePacket(p gopacket.Packet) string {
	nl := p.NetworkLayer()
	if nl == nil {
		return "wtf?"
	}
	src, dst := nl.NetworkFlow().Endpoints()
	var sport, dport gopacket.Endpoint
	tl := p.TransportLayer()
	if tl != nil {
		sport, dport = tl.TransportFlow().Endpoints()
	}
	return fmt.Sprintf("%s:%s %s:%s", src, sport, dst, dport)
}

func doSniff(intf string, worker int) {
	log.Printf("Starting worker %d", worker)
	var err error
	handle, err := pcap.OpenLive(intf, 9000, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter("vlan and (ip or ip6) and not host 192.168.2.230")
	if err != nil { // optional
		panic(err)
	}

	outf, err := os.Create(fmt.Sprintf("out_%02d.pcap", worker))
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
			//log.Println("NEW", flw, flow)
		} else {
			flw.count += 1
			flw.last = time.Now()
			if flw.count < 100 {
				//log.Println(flow, flw, "continues")
				outputPackets += 1
				err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				if err != nil {
					log.Fatal("Error writing output pcap", err)
				}
			}
		}
		//Cleanup
		if totalPackets%packetCountInterval == 0 && time.Since(lastcleanup) > packetTimeInterval {
			lastcleanup = time.Now()
			var remove []string
			for flow, flw := range seen {
				if lastcleanup.Sub(flw.last) > 5*time.Second {
					if flw.count > 100 {
						log.Println("TO ", flw, flow)
					}
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

func main() {
	workerCountString := os.Getenv("SNF_NUM_RINGS")
	var workerCount int
	workerCount = 1
	if workerCountString != "" {
		i, err := strconv.Atoi(workerCountString)
		if err != nil {
			log.Fatal(err)
		}
		workerCount = i
	}

	intf := os.Args[1]
	log.Printf("Starting capture on %s with %d workers", intf, workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go doSniff(intf, worker)
	}
	for {
		time.Sleep(time.Hour)
	}
}

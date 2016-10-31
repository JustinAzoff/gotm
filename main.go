package main

import (
	"flag"
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

var (
	iface               string
	filter              string
	packetCountInterval int
	packetTimeInterval  time.Duration
	flowTimeout         time.Duration
)

func init() {
	flag.StringVar(&iface, "interface", "en0", "Interface")
	flag.StringVar(&filter, "filter", "ip or ip6", "bpf filter")
	flag.IntVar(&packetCountInterval, "countinterval", 5000, "Interval between cleanups")
	flag.DurationVar(&packetTimeInterval, "timeinterval", 5*time.Second, "Interval between cleanups")
	flag.DurationVar(&flowTimeout, "flowtimeout", 5*time.Second, "Flow inactivity timeout")
}

type trackedFlow struct {
	count int
	last  time.Time
}

func (t trackedFlow) String() string {
	return fmt.Sprintf("packets=%d last=%s", t.count, t.last)
}

func doSniff(intf string, worker int) {
	log.Printf("Starting worker %d", worker)
	var err error
	handle, err := pcap.OpenLive(intf, 9000, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter(filter)
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

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var srcdstip, srcdstport, flow string
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6, &tcp, &udp)
	decoded := []gopacket.LayerType{}
	for {
		packetData, ci, err := handle.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		totalPackets += 1

		err = parser.DecodeLayers(packetData, &decoded)
		srcdstip = ""
		srcdstport = ""
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				srcdstip = string(ip6.SrcIP) + string(ip6.DstIP)
			case layers.LayerTypeIPv4:
				srcdstip = string(ip4.SrcIP) + string(ip4.DstIP)
			case layers.LayerTypeUDP:
				srcdstport = string(udp.SrcPort) + string(udp.DstPort)
			case layers.LayerTypeTCP:
				srcdstport = string(tcp.SrcPort) + string(tcp.DstPort)
			}
		}
		flow = srcdstip + srcdstport

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
				err = pcapWriter.WritePacket(ci, packetData)
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
				if lastcleanup.Sub(flw.last) > flowTimeout {
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
	flag.Parse()

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

	log.Printf("Starting capture on %s with %d workers", iface, workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go doSniff(iface, worker)
	}
	for {
		time.Sleep(time.Hour)
	}
}

package main

import (
	"compress/gzip"
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
	iface              string
	filter             string
	packetTimeInterval time.Duration
	flowTimeout        time.Duration
)

func init() {
	flag.StringVar(&iface, "interface", "en0", "Interface")
	flag.StringVar(&filter, "filter", "ip or ip6", "bpf filter")
	flag.DurationVar(&packetTimeInterval, "timeinterval", 5*time.Second, "Interval between cleanups")
	flag.DurationVar(&flowTimeout, "flowtimeout", 5*time.Second, "Flow inactivity timeout")
}

type trackedFlow struct {
	packets   int
	bytecount int
	last      time.Time
}

type PcapFrame struct {
	ci   gopacket.CaptureInfo
	data []byte
}

func (t trackedFlow) String() string {
	return fmt.Sprintf("bytecount=%d last=%s", t.bytecount, t.last)
}

func doSniff(intf string, worker int, writerchan chan PcapFrame) {
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
	var speedup int
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
				//log.Println(worker, ip4.SrcIP, ip4.DstIP)
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
				packets:   1,
				bytecount: len(packetData) - 64,
				last:      time.Now(),
			}
			seen[flow] = flw
			//log.Println("NEW", flw, flow)
		} else {
			flw.last = time.Now()
			if flw.bytecount < 4096 && flw.packets < 40 {
				flw.packets += 1
				flw.bytecount += len(packetData) - 64
				//log.Println(flow, flw, "continues")
				outputPackets += 1

				writerchan <- PcapFrame{ci, packetData}
			}
		}
		//Cleanup
		speedup++
		if speedup == 1000 {
			speedup = 0
			if time.Since(lastcleanup) > packetTimeInterval {
				lastcleanup = time.Now()
				stats, err := handle.Stats()
				if err != nil {
					log.Fatal(err)
				}
				//seen = make(map[string]*trackedFlow)
				var remove []string
				for flow, flw := range seen {
					if lastcleanup.Sub(flw.last) > flowTimeout {
						remove = append(remove, flow)
					}
				}
				for _, rem := range remove {
					delete(seen, rem)
				}
				log.Printf("W%02d conns=%d removed=%d pkts=%d output=%d outpct=%d recvd=%d dropped=%d ifdropped=%d",
					worker, len(seen), len(remove),
					totalPackets, outputPackets, 100*outputPackets/totalPackets,
					stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
			}
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

	outf, err := os.Create(fmt.Sprintf("out.pcap.gz"))
	outgz := gzip.NewWriter(outf)
	pcapWriter := pcapgo.NewWriter(outgz)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.

	pcapWriterChan := make(chan PcapFrame, 500000)

	log.Printf("Starting capture on %s with %d workers", iface, workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go doSniff(iface, worker, pcapWriterChan)
	}

	for pcf := range pcapWriterChan {
		err = pcapWriter.WritePacket(pcf.ci, pcf.data)
		if err != nil {
			log.Fatal("Error writing output pcap", err)
		}
	}
}

package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	MAX_ETHERNET_MTU = 9216
)

var (
	iface              string
	filter             string
	packetTimeInterval time.Duration
	flowTimeout        time.Duration
	writeOutputPath    string

	rotationInterval time.Duration
)

func init() {
	flag.StringVar(&iface, "interface", "en0", "Interface")
	flag.StringVar(&filter, "filter", "ip or ip6", "bpf filter")
	flag.DurationVar(&packetTimeInterval, "timeinterval", 5*time.Second, "Interval between cleanups")
	flag.DurationVar(&flowTimeout, "flowtimeout", 5*time.Second, "Flow inactivity timeout")
	flag.StringVar(&writeOutputPath, "write", "out", "Base output path+filename")
	flag.DurationVar(&rotationInterval, "rotationinterval", 300*time.Second, "Interval between pcap rotations")
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

type FiveTuple struct {
	proto         layers.IPProtocol
	networkFlow   gopacket.Flow
	transportFlow gopacket.Flow
}

func (t trackedFlow) String() string {
	return fmt.Sprintf("bytecount=%d last=%s", t.bytecount, t.last)
}

func mustAtoiWithDefault(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func doSniff(intf string, worker int, writerchan chan PcapFrame) {
	log.Printf("Starting worker %d", worker)
	var err error
	handle, err := pcap.OpenLive(intf, MAX_ETHERNET_MTU, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = handle.SetBPFFilter(filter)
	if err != nil { // optional
		panic(err)
	}

	seen := make(map[FiveTuple]*trackedFlow)
	totalPackets := 0
	outputPackets := 0
	lastcleanup := time.Now()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
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
		var flow FiveTuple
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				flow.proto = ip6.NextHeader
				flow.networkFlow = ip6.NetworkFlow()
			case layers.LayerTypeIPv4:
				flow.proto = ip4.Protocol
				flow.networkFlow = ip4.NetworkFlow()
				//log.Println(worker, ip4.SrcIP, ip4.DstIP)
			case layers.LayerTypeUDP:
				flow.transportFlow = udp.TransportFlow()
			case layers.LayerTypeTCP:
				flow.transportFlow = tcp.TransportFlow()
			}
		}

		flw := seen[flow]
		if flw == nil {
			flw = &trackedFlow{}
			seen[flow] = flw
			//log.Println("NEW", flw, flow)
		}
		flw.last = time.Now()
		if flw.bytecount < 4096 && flw.packets < 40 {
			flw.packets += 1
			flw.bytecount += len(packetData) - 64
			//log.Println(flow, flw, "continues")
			outputPackets += 1

			packetDataCopy := make([]byte, len(packetData))
			copy(packetDataCopy, packetData)

			writerchan <- PcapFrame{ci, packetDataCopy}
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
				var remove []FiveTuple
				for flow, flw := range seen {
					if lastcleanup.Sub(flw.last) > flowTimeout {
						remove = append(remove, flow)
					}
				}
				for _, rem := range remove {
					delete(seen, rem)
				}
				log.Printf("W%02d conns=%d removed=%d pkts=%d output=%d outpct=%.1f recvd=%d dropped=%d ifdropped=%d",
					worker, len(seen), len(remove),
					totalPackets, outputPackets, 100*float64(outputPackets)/float64(totalPackets),
					stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
			}
		}
	}
}

type gzippedPcapWrapper struct {
	w io.WriteCloser
	z *gzip.Writer
	*pcapgo.Writer
}

func (wrapper *gzippedPcapWrapper) Close() error {
	gzerr := wrapper.z.Close()
	ferr := wrapper.w.Close()

	if gzerr != nil {
		return gzerr
	}
	if ferr != nil {
		return ferr
	}

	return nil
}

func openPcap(baseFilename string) (*gzippedPcapWrapper, error) {
	tempName := fmt.Sprintf("%s_current.pcap.gz.tmp", baseFilename)
	log.Printf("Opening new pcap file %s", tempName)
	outf, err := os.Create(tempName)
	if err != nil {
		return nil, err
	}
	outgz := gzip.NewWriter(outf)
	pcapWriter := pcapgo.NewWriter(outgz)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
	return &gzippedPcapWrapper{outf, outgz, pcapWriter}, nil
}

func renamePcap(baseFilename string) error {
	tempName := fmt.Sprintf("%s_current.pcap.gz.tmp", baseFilename)
	datePart := time.Now().Format("2006-01-02T15-04-05")
	newName := fmt.Sprintf("%s_%s.pcap.gz", baseFilename, datePart)
	err := os.Rename(tempName, newName)

	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		log.Printf("moved %s to %s", tempName, newName)
	}
	return nil
}

func main() {
	flag.Parse()

	workerCountString := os.Getenv("SNF_NUM_RINGS")
	workerCount := mustAtoiWithDefault(workerCountString, 1)

	pcapWriterChan := make(chan PcapFrame, 500000)

	log.Printf("Starting capture on %s with %d workers", iface, workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go doSniff(iface, worker, pcapWriterChan)
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	rotationTicker := time.NewTicker(rotationInterval)

	//Rename any leftover pcap files from a previous run
	renamePcap(writeOutputPath)

	var pcapWriter *gzippedPcapWrapper
	pcapWriter, err := openPcap(writeOutputPath)
	if err != nil {
		log.Fatal("Error opening pcap", err)
	}

	for {
		select {
		case pcf := <-pcapWriterChan:
			err := pcapWriter.WritePacket(pcf.ci, pcf.data)
			if err != nil {
				pcapWriter.Close()
				log.Fatal("Error writing output pcap", err)
			}

		case <-rotationTicker.C:
			log.Print("Rotating")
			//FIXME: refactor/wrap the open/close/rename code?
			err = pcapWriter.Close()
			if err != nil {
				log.Fatal("Error closing pcap", err)
			}
			err = renamePcap(writeOutputPath)
			if err != nil {
				log.Fatal("Error renaming pcap", err)
			}
			pcapWriter, err = openPcap(writeOutputPath)
			if err != nil {
				log.Fatal("Error opening pcap", err)
			}

		case <-signals:
			log.Print("Control-C??")
			err = pcapWriter.Close()
			if err != nil {
				log.Fatal("Error Closing", err)
			}
			err = renamePcap(writeOutputPath)
			if err != nil {
				log.Fatal("Error renaming pcap", err)
			}
			os.Exit(0)
		}
	}
}

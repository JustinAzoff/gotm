package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	MAX_ETHERNET_MTU       = 9216
	MINIMUM_IP_PACKET_SIZE = 58
	LARGE_FLOW_SIZE        = 1024 * 1024 * 1024 * 8 //1 GB
)

var (
	metricsAddress string

	iface              string
	filter             string
	packetTimeInterval time.Duration
	flowTimeout        time.Duration
	writeOutputPath    string

	rotationInterval time.Duration
)

//Metrics
var (
	labels = []string{
		// Which interface
		"interface",
		// Which worker
		"worker",
	}

	mActiveFlows = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_active_flow_count",
			Help: "Current number of active flows",
		}, labels,
	)
	mExpired = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_expired_flow_count",
			Help: "Current number of expired flows in the last packetTimeInterval",
		}, labels,
	)
	mBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_bytes_total",
			Help: "Number of bytes seen",
		}, labels,
	)
	mBytesOutput = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_bytes_output_total",
			Help: "Number of bytes output after filtering",
		}, labels,
	)
	mPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_packet_count",
			Help: "Number of packets seen",
		}, labels,
	)
	mOutput = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_packet_output_count",
			Help: "Number of packets output after filtering",
		}, labels,
	)
	mFlows = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gotm_flow_count",
			Help: "Number of flows seen",
		}, labels,
	)

	// These should be gauges, but can't.. https://github.com/prometheus/client_golang/issues/309
	mReceived = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_packet_nic_received",
			Help: "Number of packets received by NIC",
		}, labels,
	)
	mDropped = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_packet_nic_dropped",
			Help: "Number of packets dropped by NIC",
		}, labels,
	)
	mIfDropped = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gotm_packet_nic_if_dropped",
			Help: "Number of packets dropped by NIC at the interface",
		}, labels,
	)
)

func init() {
	flag.StringVar(&metricsAddress, "metrics-address", ":8080", "The address to listen on for HTTP requests for /metrics.")
	flag.StringVar(&iface, "interface", "eth0", "Comma separated list of interfaces")
	flag.StringVar(&filter, "filter", "ip or ip6", "bpf filter")
	flag.DurationVar(&packetTimeInterval, "timeinterval", 5*time.Second, "Interval between cleanups")
	flag.DurationVar(&flowTimeout, "flowtimeout", 5*time.Second, "Flow inactivity timeout")
	flag.StringVar(&writeOutputPath, "write", "out", "Output path is $writeOutputPath/yyyy/mm/dd/ts.pcap")
	flag.DurationVar(&rotationInterval, "rotationinterval", 300*time.Second, "Interval between pcap rotations")

	prometheus.MustRegister(mActiveFlows)
	prometheus.MustRegister(mExpired)
	prometheus.MustRegister(mPackets)
	prometheus.MustRegister(mOutput)
	prometheus.MustRegister(mBytes)
	prometheus.MustRegister(mBytesOutput)
	prometheus.MustRegister(mFlows)
	prometheus.MustRegister(mReceived)
	prometheus.MustRegister(mDropped)
	prometheus.MustRegister(mIfDropped)
}

type trackedFlow struct {
	packets   uint
	bytecount uint
	last      time.Time
	logged    bool
}

func (t trackedFlow) String() string {
	return fmt.Sprintf("packets=%d bytecount=%d last=%s", t.packets, t.bytecount, t.last)
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

func (f FiveTuple) String() string {
	src, dst := f.networkFlow.Endpoints()
	sport, dport := f.transportFlow.Endpoints()
	return fmt.Sprintf("src=%s sport=%s dst=%s dport=%s", src, sport, dst, dport)
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
	runtime.LockOSThread()
	log.Printf("Starting worker %d on interface %s", worker, intf)
	workerString := fmt.Sprintf("%d", worker)

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
	var totalFlows, removedFlows, totalBytes, outputBytes, totalPackets, outputPackets uint
	var pcapStats *pcap.Stats
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
		totalBytes += uint(len(packetData))

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
			totalFlows += 1
		}
		flw.last = time.Now()
		flw.packets += 1
		pl := uint(len(packetData))
		if pl > MINIMUM_IP_PACKET_SIZE {
			flw.bytecount += pl - MINIMUM_IP_PACKET_SIZE
		}
		if flw.bytecount < 4096 && flw.packets < 40 {
			//log.Println(flow, flw, "continues")
			outputPackets += 1
			outputBytes += uint(len(packetData))

			packetDataCopy := make([]byte, len(packetData))
			copy(packetDataCopy, packetData)

			writerchan <- PcapFrame{ci, packetDataCopy}
		} else if flw.logged == false && flw.bytecount > LARGE_FLOW_SIZE {
			log.Printf("Large flow over 8GB: %s", flow)
			flw.logged = true
		}
		//Cleanup
		speedup++
		if speedup == 5000 {
			speedup = 0
			pcapStats, err = handle.Stats()
			if err != nil {
				log.Fatal(err)
			}
			if time.Since(lastcleanup) > packetTimeInterval {
				lastcleanup = time.Now()
				//seen = make(map[string]*trackedFlow)
				var remove []FiveTuple
				for flow, flw := range seen {
					if lastcleanup.Sub(flw.last) > flowTimeout {
						remove = append(remove, flow)
						removedFlows += 1
					}
				}
				for _, rem := range remove {
					delete(seen, rem)
				}
				log.Printf("if=%s W=%02d flows=%d removed=%d bytes=%d pkts=%d output=%d outpct=%.1f recvd=%d dropped=%d ifdropped=%d",
					intf, worker, len(seen), len(remove),
					totalBytes, totalPackets, outputPackets, 100*float64(outputPackets)/float64(totalPackets),
					pcapStats.PacketsReceived, pcapStats.PacketsDropped, pcapStats.PacketsIfDropped)

				mExpired.WithLabelValues(intf, workerString).Set(float64(len(remove)))
			}
			mActiveFlows.WithLabelValues(intf, workerString).Set(float64(len(seen)))

			mFlows.WithLabelValues(intf, workerString).Add(float64(totalFlows))
			totalFlows = 0

			mPackets.WithLabelValues(intf, workerString).Add(float64(totalPackets))
			totalPackets = 0

			mBytes.WithLabelValues(intf, workerString).Add(float64(totalBytes))
			totalBytes = 0

			mBytesOutput.WithLabelValues(intf, workerString).Add(float64(outputBytes))
			outputBytes = 0

			mOutput.WithLabelValues(intf, workerString).Add(float64(outputPackets))
			outputPackets = 0

			mReceived.WithLabelValues(intf, workerString).Set(float64(pcapStats.PacketsReceived))
			mDropped.WithLabelValues(intf, workerString).Set(float64(pcapStats.PacketsDropped))
			mIfDropped.WithLabelValues(intf, workerString).Set(float64(pcapStats.PacketsIfDropped))
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
	log.Printf("Opening new pcap file %s", baseFilename)
	outf, err := os.Create(baseFilename)
	if err != nil {
		return nil, err
	}
	outgz := gzip.NewWriter(outf)
	pcapWriter := pcapgo.NewWriter(outgz)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
	return &gzippedPcapWrapper{outf, outgz, pcapWriter}, nil
}

//renamePcap renames the 'current' file to
//writeOutputPath/yyy/mm/dd/yyyy-mm-ddThh-mm-ss.pcap.gz

func renamePcap(tempName, outputPath string) error {
	datePart := time.Now().Format("2006/01/02/2006-01-02T15-04-05.pcap.gz")

	newName := filepath.Join(outputPath, datePart)
	//Ensure the directori exists
	if err := os.MkdirAll(filepath.Dir(newName), 0700); err != nil {
		return err
	}
	err := os.Rename(tempName, newName)

	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		log.Printf("moved %s to %s", tempName, newName)
	}
	return nil
}

func metrics() {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(metricsAddress, nil)
	if err != nil {
		log.Print(err)
	}
	//Not fatal?
}

func main() {
	flag.Parse()

	go metrics()

	currentFileName := fmt.Sprintf("%s_current.pcap.gz.tmp", iface)
	workerCountString := os.Getenv("SNF_NUM_RINGS")
	workerCount := mustAtoiWithDefault(workerCountString, 1)

	pcapWriterChan := make(chan PcapFrame, 500000)

	interfaceList := strings.Split(iface, ",")

	for _, iface := range interfaceList {
		log.Printf("Starting capture on %s with %d workers", iface, workerCount)
		for worker := 0; worker < workerCount; worker++ {
			go doSniff(iface, worker, pcapWriterChan)
		}
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	rotationTicker := time.NewTicker(rotationInterval)

	//Rename any leftover pcap files from a previous run
	renamePcap(currentFileName, writeOutputPath)

	var pcapWriter *gzippedPcapWrapper
	pcapWriter, err := openPcap(currentFileName)
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
			err = renamePcap(currentFileName, writeOutputPath)
			if err != nil {
				log.Fatal("Error renaming pcap", err)
			}
			pcapWriter, err = openPcap(currentFileName)
			if err != nil {
				log.Fatal("Error opening pcap", err)
			}

		case <-signals:
			log.Print("Control-C??")
			err = pcapWriter.Close()
			if err != nil {
				log.Fatal("Error Closing", err)
			}
			err = renamePcap(currentFileName, writeOutputPath)
			if err != nil {
				log.Fatal("Error renaming pcap", err)
			}
			os.Exit(0)
		}
	}
}

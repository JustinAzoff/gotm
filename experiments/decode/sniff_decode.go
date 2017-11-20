package main

import (
	"io"
	"log"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {

	var err error
	handle, err := pcap.OpenLive(os.Args[1], 9000, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	cf, err := os.Create("sniff.cpuprofile")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(cf)
	defer pprof.StopCPUProfile()

	var m runtime.MemStats
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6, &tcp, &udp)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}
	for i := 0; i < 1000000; i++ {
		packetData, _, err := handle.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		err = parser.DecodeLayers(packetData, &decoded)
		if err != nil {
			log.Printf("%v", err)
		}
		if i%100000 == 0 {
			runtime.ReadMemStats(&m)
			log.Printf("Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v\n", m.Alloc/1024, m.TotalAlloc/1024, m.Sys/1024, m.NumGC)
		}
	}

	f, err := os.Create("sniff.profile")
	if err != nil {
		log.Fatal(err)
	}
	pprof.WriteHeapProfile(f)
	f.Close()
}

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
)

type NetData struct {
	LayerEthernet struct {
		EthernetType   string
		SourceMAC      string
		DestinationMAC string
	}
	LayerIP struct {
		TTL                int
		NetworkFlow        string
		Protocol           string
		SourceAddress      string
		DestinationAddress string
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter a value (interface, sniffer(default) or pcap): ")
	scanner.Scan()

	input := scanner.Text()
	switch input {
	case "interface":
		InterfacesDiscovery()
	case "sniffer":
		NetSniffer()
	case "pcap":
		Pcap()
	default:
		NetSniffer()
	}
}

func InterfacesDiscovery() {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("error retrieving devices - %v", err)
	}

	for _, interf := range interfaces {
		fmt.Printf("Interface Name: %s\n", interf.Name)
		fmt.Printf("Interface Description: %s\n", interf.Description)
		fmt.Printf("Interface Flags: %d\n", interf.Flags)
		for _, iaddress := range interf.Addresses {
			fmt.Printf("\tIP: %s\n", iaddress.IP)
			fmt.Printf("\tNetMask: %s\n", iaddress.Netmask)
		}
		fmt.Println("******************************************")
	}
}

func NetSniffer() {
	var filter = flag.String("filter", "", "BPF filter for capture")
	var iface = flag.String("iface", "eth0", "Select interface where to capture")
	var snaplen = flag.Int("snaplen", 1024, "Maximun sise to read for each packet")
	var promisc = flag.Bool("promisc", false, "Enable promiscuous mode")
	var fileLogs = flag.String("fileLogs", "../../infra/volumes/sniffer/network.log", "Network logs destination")
	//var timeoutT = flag.Int("timeout", 30, "Connection Timeout in seconds")

	log.Println("start")
	defer log.Println("end")

	flag.Parse()

	//var timeout time.Duration = time.Duration(*timeoutT) * time.Second

	// Opening Device
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// Applying BPF Filter if it exists
	if *filter != "" {
		log.Println("applying filter ", *filter)
		err := handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatalf("error applyign BPF Filter %s - %v", *filter, err)
		}
	}

	file, err := os.Create(*fileLogs)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	logger := log.New(file, "", log.LstdFlags)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Print the packet details

		var netInfo NetData
		// Extract and print the Ethernet layer
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			ethPacket, _ := ethLayer.(*layers.Ethernet)
			netInfo.LayerEthernet.EthernetType = ethPacket.EthernetType.String()
			netInfo.LayerEthernet.SourceMAC = ethPacket.SrcMAC.String()
			netInfo.LayerEthernet.DestinationMAC = ethPacket.DstMAC.String()
		}

		// Extract and print the IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ipPacket, _ := ipLayer.(*layers.IPv4)
			netInfo.LayerIP.TTL = int(ipPacket.TTL)
			netInfo.LayerIP.NetworkFlow = ipPacket.NetworkFlow().String()
			netInfo.LayerIP.Protocol = ipPacket.Protocol.String()
			netInfo.LayerIP.SourceAddress = ipPacket.SrcIP.String()
			netInfo.LayerIP.DestinationAddress = ipPacket.SrcIP.String()
		}

		bytesInfo, err := json.Marshal(netInfo)
		if err != nil {
			log.Fatalf("marshal error - %v", err)
			break
		}
		logger.Println(string(bytesInfo))

		//logger.Println(packet)
	}

}

func Pcap() {
	var fname = flag.String("pcap", "/mnt/c/Users/dmytro.zilnyk/Downloads/testnet.pcap", "Pcap File to load and parse")
	var filter = flag.String("filter", "", "BPF Filter to apply")

	log.Println("start")
	defer log.Println("end")

	flag.Parse()

	// Check if file has been passed, otherwise print help
	if *fname == "" {
		flag.PrintDefaults()
		log.Fatalf("no pcap file parameter was passed")
	}

	pcapHandle, err := pcap.OpenOffline(*fname)
	if err != nil {
		log.Fatalf("error opening file - %v", err)
	}

	defer pcapHandle.Close()

	if *filter != "" {
		err = pcapHandle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatalf("error appling filter %s - %v", *filter, err)
		}
	}

	packetsFiltered := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	for packet := range packetsFiltered.Packets() {
		fmt.Println(packet)
	}
}

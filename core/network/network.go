package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

func main() {

}

func test1() {
	type FlowKey struct {
		SrcIP    string
		DstIP    string
		SrcPort  string
		DstPort  string
		Protocol string
	}

	type Flow struct {
		FlowKey     FlowKey
		Packets     [][]byte
		StartPacket gopacket.Packet
		EndPacket   gopacket.Packet
	}

	// Open the pcap file for reading
	handle, err := pcap.OpenLive("eth0", int32(1024), false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// Create a map to store flows
	flows := make(map[FlowKey]*Flow)

	// Start capturing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for packet := range packetSource.Packets() {
			fmt.Println("test")
			// Get the network layer of the packet
			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}

			// Get the transport layer of the packet
			transportLayer := packet.TransportLayer()
			if transportLayer == nil {
				continue
			}

			// Create a flow key to identify the flow
			flowKey := FlowKey{
				SrcIP:    networkLayer.NetworkFlow().Src().String(),
				DstIP:    networkLayer.NetworkFlow().Dst().String(),
				SrcPort:  transportLayer.TransportFlow().Src().String(),
				DstPort:  transportLayer.TransportFlow().Dst().String(),
				Protocol: networkLayer.NetworkFlow().String(),
			}

			// Check if flow already exists
			if flow, ok := flows[flowKey]; ok {
				// Update the end packet of the flow
				flow.EndPacket = packet

				// Add the packet data to the flow
				flow.Packets = append(flow.Packets, packet.Data())
			} else {
				// Create a new flow
				newFlow := &Flow{
					FlowKey:     flowKey,
					Packets:     [][]byte{packet.Data()},
					StartPacket: packet,
					EndPacket:   packet,
				}

				// Add the flow to the map
				flows[flowKey] = newFlow
			}
		}
	}()

	time.Sleep(30 * time.Second)

	// Print the captured flows
	for _, flow := range flows {
		fmt.Println("Flow Key:", flow.FlowKey)
		fmt.Println("Start Time:", flow.StartPacket.Metadata().Timestamp)
		fmt.Println("End Time:", flow.EndPacket.Metadata().Timestamp)
		fmt.Println("Total Packets:", len(flow.Packets))
		fmt.Println("")

		// Access and process individual packets in the flow
		//for _, packetData := range flow.Packets {
		//	// Process each packet data
		//	// ...
		//}
	}
}

func test2() {
	type TCPStream struct {
		SourceIP        string
		DestinationIP   string
		SourcePort      layers.TCPPort
		DestinationPort layers.TCPPort
		Data            []byte
	}

	// Open the pcap file for reading
	handle, err := pcap.OpenOffline("packets.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create a map to store TCP streams
	tcpStreams := make(map[string]*TCPStream)

	// Start capturing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Get the transport layer of the packet
		transportLayer := packet.TransportLayer()
		if transportLayer == nil || transportLayer.LayerType() != layers.LayerTypeTCP {
			continue
		}

		// Get the TCP layer of the packet
		tcpLayer := transportLayer.(*layers.TCP)
		if tcpLayer.SYN || tcpLayer.FIN {
			// Skip SYN and FIN packets
			continue
		}

		// Create a unique identifier for the TCP stream
		streamID := fmt.Sprintf("%s:%d-%s:%d", packet.NetworkLayer().NetworkFlow().Src().String(), tcpLayer.SrcPort, packet.NetworkLayer().NetworkFlow().Dst().String(), tcpLayer.DstPort)

		// Check if the TCP stream already exists
		if _, ok := tcpStreams[streamID]; !ok {
			tcpStreams[streamID] = &TCPStream{
				SourceIP:        packet.NetworkLayer().NetworkFlow().Src().String(),
				DestinationIP:   packet.NetworkLayer().NetworkFlow().Dst().String(),
				SourcePort:      tcpLayer.SrcPort,
				DestinationPort: tcpLayer.DstPort,
				Data:            tcpLayer.Payload,
			}
		} else {
			// Append the packet data to the existing TCP stream
			tcpStreams[streamID].Data = append(tcpStreams[streamID].Data, tcpLayer.Payload...)
		}
	}

	// Print the captured TCP streams
	for _, stream := range tcpStreams {
		fmt.Println("Source IP:", stream.SourceIP)
		fmt.Println("Destination IP:", stream.DestinationIP)
		fmt.Println("Source Port:", stream.SourcePort)
		fmt.Println("Destination Port:", stream.DestinationPort)
		fmt.Println("Data:", string(stream.Data))
		fmt.Println("")
	}

}

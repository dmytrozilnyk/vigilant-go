package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Obtener la lista de interfaces de red disponibles
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	// Recorrer cada interfaz de red
	for _, iface := range ifaces {
		// Abrir la interfaz de red para capturar paquetes
		handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			log.Println(err)
			continue
		}
		defer handle.Close()

		// Filtrar paquetes ARP
		err = handle.SetBPFFilter("arp")
		if err != nil {
			log.Println(err)
			continue
		}

		// Escuchar paquetes
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// Obtener la capa ARP del paquete
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arpPacket, _ := arpLayer.(*layers.ARP)

				// Filtrar solo los paquetes ARP de tipo "who-has"
				if arpPacket.Operation == layers.ARPRequest {
					// Obtener la dirección IP y dirección MAC del dispositivo
					ip := net.IP(arpPacket.DstProtAddress).String()
					mac := net.HardwareAddr(arpPacket.SourceHwAddress).String()

					fmt.Printf("IP: %s, MAC: %s\n", ip, mac)
				}
			}
		}
	}
}

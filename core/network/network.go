package main

import (
	"fmt"
	"github.com/shirou/gopsutil/net"
)

func main() {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Failed to retrieve network interfaces:", err)
		return
	}

	for _, iface := range interfaces {
		fmt.Println("Interface:", iface.Name)

		stats, err := net.IOCountersByFile(false, "test")
		if err != nil {
			fmt.Println("Failed to retrieve network interface stats:", err)
			continue
		}

		for _, stat := range stats {
			if stat.Name == iface.Name {
				fmt.Println("Bytes received:", stat.BytesRecv)
				fmt.Println("Bytes transmitted:", stat.BytesSent)
				fmt.Println("Packets received:", stat.PacketsRecv)
				fmt.Println("Packets transmitted:", stat.PacketsSent)
			}
		}
	}
}

package main

import (
	"fmt"
	"github.com/dmytrozilnyk/vigilant-go/core/network/test3/pcap"
)

func main() {
	closeChan := make(chan struct{})
	p := pcap.NewNetworkTrafficParser(1.0)
	chanResp, err := p.ParseFromInterface("eth0", "", closeChan)
	if err != nil {
		panic(err)
	}

	for traffic := range chanResp {
		fmt.Println(traffic.SrcIP.String())
		fmt.Println(traffic.DstIP.String())
	}
}

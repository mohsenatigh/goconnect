package vnet

import (
	"log"
	"testing"
)

func TestProcess(t *testing.T) {

	packetFactory := CreateProcessFactory()

	//check send packet
	sendPacket := packetFactory.CreateProcessInfoByName("dns_reqv4")
	receivePacket := packetFactory.CreateProcessInfoByName("dns_resv4")

	if sendPacket.GetFlowKey() == 0 {
		log.Fatalf("invalid flow key")
	}

	if sendPacket.GetFlowKey() != receivePacket.GetFlowKey() {
		log.Fatalf("invalid flow key")
	}
}

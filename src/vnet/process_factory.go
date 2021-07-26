package vnet

import (
	"encoding/hex"
	"goconnect/common"
	"log"
	"math/rand"
)

//sample packets
type sMockPacketInfo struct {
	Name    string
	HexData string
}

var gMockPacketsInfo = []sMockPacketInfo{
	{Name: "dns_reqv4", HexData: "45000038e6364000401181fec0a801c808080808dfcd0035002476b5c2b40100000100000000000006676f6f676c6503636f6d0000010001"},
	{Name: "dns_resv4", HexData: "45000048d84c000072119dd808080808c0a801c80035dfcd0034dec1c2b48180000100010000000006676f6f676c6503636f6d0000010001c00c00010001000000770004acd9a9ee"},
}

//---------------------------------------------------------------------------------------
type cProcessFactory struct {
}

//---------------------------------------------------------------------------------------

//CreateProcessInfo for IProcessFactory
func (thisPt *cProcessFactory) CreateProcessInfo(buffer []byte) common.IProcessInfo {
	process := new(cProcess)
	process.Init(buffer)
	return process
}

//---------------------------------------------------------------------------------------

//FreeProcessInfo for IProcessFactory
func (thisPt *cProcessFactory) FreeProcessInfo(process common.IProcessInfo) {
	packet, res := process.(*cProcess)

	if res == false {
		log.Printf("invalid process object")
		return
	}

	packet.Free()
}

//---------------------------------------------------------------------------------------

//CreateProcessInfoByName for IProcessFactory
func (thisPt *cProcessFactory) CreateProcessInfoByName(name string) common.IProcessInfo {
	for _, info := range gMockPacketsInfo {
		if info.Name == name {
			data, _ := hex.DecodeString(info.HexData)
			packet := thisPt.CreateProcessInfo(data)
			packet.ProcessAsNetPacket()
			return packet
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------

//CreateRandomProcessInfoByName for IProcessFactory
func (thisPt *cProcessFactory) CreateRandomProcessInfoByName(name string) common.IProcessInfo {
	for _, info := range gMockPacketsInfo {
		if info.Name == name {
			data, _ := hex.DecodeString(info.HexData)
			packet := thisPt.CreateProcessInfo(data)
			packet.ProcessAsNetPacket()

			//randomize info
			packetObj := packet.(*cProcess)
			packetObj.srcIP[0] = byte(rand.Uint32() % 255)
			packetObj.srcIP[1] = byte(rand.Uint32() % 255)
			packetObj.dstIP[0] = byte(rand.Uint32() % 255)
			packetObj.dstIP[1] = byte(rand.Uint32() % 255)
			packetObj.calculateFlowKey()
			return packet
		}
	}
	return nil
}

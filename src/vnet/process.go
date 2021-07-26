package vnet

import (
	"encoding/binary"
	"fmt"
	"goconnect/common"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type cProcess struct {
	buffer          [4096]byte
	usedSize        uint32
	ipVersion       uint8
	l4Protocol      uint8
	srcPort         uint16
	dstPort         uint16
	srcIP           net.IP
	dstIP           net.IP
	clientIP        net.IP
	clientVirtualIP net.IP
	inNIC           uint64
	outNIC          uint64
	flowKey         uint64
	srcIPIndex      uint64
	dstIPIndex      uint64
	applicationData []byte
}

//---------------------------------------------------------------------------------------
func (thisPt *cProcess) calculateFlowKey() {

	if thisPt.ipVersion == 4 {
		thisPt.srcIPIndex = uint64(binary.LittleEndian.Uint32([]byte(thisPt.srcIP)))
		thisPt.dstIPIndex = uint64(binary.LittleEndian.Uint32([]byte(thisPt.dstIP)))
	} else {
		calcV6Index := func(ip net.IP) uint64 {
			data := []byte(ip)
			p1 := binary.LittleEndian.Uint64(data[:8])
			p2 := binary.LittleEndian.Uint64(data[8:])
			return (p1 ^ p2)
		}
		thisPt.srcIPIndex = calcV6Index(thisPt.srcIP)
		thisPt.dstIPIndex = calcV6Index(thisPt.dstIP)
	}
	thisPt.flowKey = (thisPt.srcIPIndex ^ thisPt.dstIPIndex)
}

//---------------------------------------------------------------------------------------

//GetBuffer for IProcessInfo
func (thisPt *cProcess) GetBuffer() []byte {
	return thisPt.buffer[0:thisPt.usedSize]
}

//---------------------------------------------------------------------------------------

//GetBuffer for IProcessInfo
func (thisPt *cProcess) GetUsedSize() uint32 {
	return thisPt.usedSize
}

//---------------------------------------------------------------------------------------

//GetClientIP for IProcessInfo
func (thisPt *cProcess) GetClientIP() net.IP {
	return thisPt.clientIP
}

//---------------------------------------------------------------------------------------

//SetClientIP for IProcessInfo
func (thisPt *cProcess) SetClientIP(ip net.IP) {
	thisPt.clientIP = ip
}

//---------------------------------------------------------------------------------------

//GetSourceIP for IProcessInfo
func (thisPt *cProcess) GetSourceIP() net.IP {
	return thisPt.srcIP
}

//---------------------------------------------------------------------------------------

//GetDestinationIP for IProcessInfo
func (thisPt *cProcess) GetDestinationIP() net.IP {
	return thisPt.dstIP
}

//---------------------------------------------------------------------------------------

//GetIPVersion for IProcessInfo
func (thisPt *cProcess) GetIPVersion() uint8 {
	return thisPt.ipVersion
}

//---------------------------------------------------------------------------------------

//GetL4Protocol for IProcessInfo
func (thisPt *cProcess) GetL4Protocol() uint8 {
	return thisPt.l4Protocol
}

//---------------------------------------------------------------------------------------

//GetSourcePort for IProcessInfo
func (thisPt *cProcess) GetSourcePort() uint16 {
	return thisPt.srcPort
}

//---------------------------------------------------------------------------------------

//GetDestinationPort for IProcessInfo
func (thisPt *cProcess) GetDestinationPort() uint16 {
	return thisPt.dstPort
}

//---------------------------------------------------------------------------------------

//GetClientVirtualIP for IProcessInfo
func (thisPt *cProcess) GetClientVirtualIP() net.IP {
	return thisPt.clientVirtualIP
}

//---------------------------------------------------------------------------------------

//SetClientVirtualIP for IProcessInfo
func (thisPt *cProcess) SetClientVirtualIP(ip net.IP) {
	thisPt.clientVirtualIP = ip
}

//---------------------------------------------------------------------------------------

//GetInNIC for IProcessInfo
func (thisPt *cProcess) GetInNIC() uint64 {
	return thisPt.inNIC
}

//---------------------------------------------------------------------------------------

//SetInNIC for IProcessInfo
func (thisPt *cProcess) SetInNIC(nic uint64) {
	thisPt.inNIC = nic
}

//---------------------------------------------------------------------------------------

//GetInNIC for IProcessInfo
func (thisPt *cProcess) GetOutNIC() uint64 {
	return thisPt.outNIC
}

//---------------------------------------------------------------------------------------

//SetInNIC for IProcessInfo
func (thisPt *cProcess) SetOutNIC(nic uint64) {
	thisPt.outNIC = nic
}

//---------------------------------------------------------------------------------------

//GetFlowKey for IProcessInfo
func (thisPt *cProcess) GetFlowKey() uint64 {
	return thisPt.flowKey
}

//---------------------------------------------------------------------------------------

//End
func (thisPt *cProcess) Free() {

}

//---------------------------------------------------------------------------------------
func (thisPt *cProcess) GetApplicationPayload() []byte {
	return thisPt.applicationData
}

//---------------------------------------------------------------------------------------
func (thisPt *cProcess) Init(buffer []byte) {
	copy(thisPt.buffer[0:], buffer)
	thisPt.usedSize = uint32(len(buffer))
}

//---------------------------------------------------------------------------------------

//ProcessAsPacket for IProcessInfo
func (thisPt *cProcess) ProcessAsNetPacket() bool {

	layer := layers.LayerTypeIPv4
	if (thisPt.buffer[0] & 0xf0) == 0x60 {
		layer = layers.LayerTypeIPv6
	}

	lpacket := gopacket.NewPacket(thisPt.buffer[:thisPt.usedSize], layer, gopacket.NoCopy)
	network := lpacket.NetworkLayer()
	transport := lpacket.TransportLayer()

	if network.LayerType() == layers.LayerTypeIPv6 {
		ipv6 := network.(*layers.IPv6)
		thisPt.srcIP = ipv6.SrcIP
		thisPt.dstIP = ipv6.DstIP
		thisPt.ipVersion = 6
		thisPt.l4Protocol = uint8(ipv6.NextHeader)
	} else if network.LayerType() == layers.LayerTypeIPv4 {
		ipv4 := network.(*layers.IPv4)
		thisPt.srcIP = ipv4.SrcIP.To4()
		thisPt.dstIP = ipv4.DstIP.To4()
		thisPt.ipVersion = 4
		thisPt.l4Protocol = uint8(ipv4.Protocol)
	} else {
		return false
	}

	//TCP or UDP
	if thisPt.l4Protocol == common.L4PROTOCOLTCP {
		tcp := transport.(*layers.TCP)
		thisPt.srcPort = uint16(tcp.SrcPort)
		thisPt.dstPort = uint16(tcp.DstPort)
	} else if thisPt.l4Protocol == common.L4PROTOCOLUDP {
		udp := transport.(*layers.UDP)
		thisPt.srcPort = uint16(udp.SrcPort)
		thisPt.dstPort = uint16(udp.DstPort)
	}

	//get application layer
	application := lpacket.ApplicationLayer()
	if application != nil {
		thisPt.applicationData = application.LayerContents()
	}

	//calculate flow key
	thisPt.calculateFlowKey()

	return true
}

//---------------------------------------------------------------------------------------

//ProcessAsPacket for IProcessInfo
func (thisPt *cProcess) String() string {
	return fmt.Sprintf("%s:%d->%s:%d %d %d", thisPt.srcIP.String(), thisPt.srcPort, thisPt.dstIP.String(), thisPt.dstPort, thisPt.l4Protocol, len(thisPt.applicationData))
}

package protocols

import (
	"goconnect/common"
	"net"
)

//---------------------------------------------------------------------------------------

type cNICBase struct {
	Ip        net.IP               `json:"ip"`
	VirtualIP net.IP               `json:"virtual_ip"`
	Id        uint64               `json:"id"`
	NicType   uint32               `json:"type"`
	Stat      common.STransferStat `json:"stat"`
	Routes    []net.IPNet
	Name      string `json:"name"`
}

//---------------------------------------------------------------------------------------

//GetID for INIC
func (thisPt *cNICBase) GetID() uint64 {
	return thisPt.Id
}

//---------------------------------------------------------------------------------------

//GetID for INIC
func (thisPt *cNICBase) GetName() string {
	return thisPt.Name
}

//---------------------------------------------------------------------------------------

//GetType for INIC
func (thisPt *cNICBase) GetType() uint32 {
	return thisPt.NicType
}

//---------------------------------------------------------------------------------------

//GetStat for INIC
func (thisPt *cNICBase) GetStat() common.STransferStat {
	return thisPt.Stat
}

//---------------------------------------------------------------------------------------

//GetPeerIP for INIC
func (thisPt *cNICBase) GetPeerIP() net.IP {
	return thisPt.Ip
}

//---------------------------------------------------------------------------------------

//GetVirtualIP for INIC
func (thisPt *cNICBase) GetVirtualIP() net.IP {
	return thisPt.VirtualIP
}

//---------------------------------------------------------------------------------------

//GetRoutes for INIC
func (thisPt *cNICBase) GetRoutes() []net.IPNet {
	return thisPt.Routes
}

//---------------------------------------------------------------------------------------

//WriteData for INIC
func (thisPt *cNICBase) WriteData(data common.IProcessInfo) {

}

//---------------------------------------------------------------------------------------

//End for INIC
func (thisPt *cNICBase) End() {

}

//---------------------------------------------------------------------------------------
func (thisPt *cNICBase) UpdateReceive(process common.IProcessInfo) {
	thisPt.Stat.ReceiveByte += uint64(process.GetUsedSize())
	thisPt.Stat.ReceivePacket++
}

//---------------------------------------------------------------------------------------
func (thisPt *cNICBase) UpdateSend(process common.IProcessInfo) {
	thisPt.Stat.SendByte += uint64(process.GetUsedSize())
	thisPt.Stat.SendPacket++
}

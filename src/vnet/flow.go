package vnet

import (
	"goconnect/common"
	"net"
)

//---------------------------------------------------------------------------------------

//cFlow ...
type cFlow struct {
	Id          uint64               `json:"id"`
	Stat        common.STransferStat `json:"stat"`
	Source      net.IP               `json:"src"`
	Destination net.IP               `json:"dst"`
	InNIC       uint64               `json:"in_nic"`
	OutNIC      uint64               `json:"out_nic"`
	Blocked     bool                 `json:"blocked"`
	InNICName   string               `json:"in_nic_name"`
	OutNICName  string               `json:"out_nic_name"`
	netManager  common.INICManager
}

//---------------------------------------------------------------------------------------

//GetStat for IFlow
func (thisPt *cFlow) GetStat() common.STransferStat {
	return thisPt.Stat
}

//---------------------------------------------------------------------------------------

//GetSource for IFlow
func (thisPt *cFlow) GetSource() net.IP {
	return thisPt.Source
}

//---------------------------------------------------------------------------------------

//GetDestinatin for IFlow
func (thisPt *cFlow) GetDestinatin() net.IP {
	return thisPt.Destination
}

//---------------------------------------------------------------------------------------

//GetInNIC for IFlow
func (thisPt *cFlow) GetInNIC() uint64 {
	return thisPt.InNIC
}

//---------------------------------------------------------------------------------------

//GetOutNIC for IFlow
func (thisPt *cFlow) GetOutNIC() uint64 {
	return thisPt.OutNIC
}

//---------------------------------------------------------------------------------------

//SetOutNIC for IFlow
func (thisPt *cFlow) SetOutNIC(nic uint64) {
	thisPt.OutNIC = nic
	thisPt.OutNICName = thisPt.netManager.GetNICName(nic)
}

//---------------------------------------------------------------------------------------

//SetOutNIC for IFlow
func (thisPt *cFlow) GetID() uint64 {
	return thisPt.Id
}

//---------------------------------------------------------------------------------------

//Blocked for IFlow
func (thisPt *cFlow) GetBlocked() bool {
	return thisPt.Blocked
}

//---------------------------------------------------------------------------------------

//GetDirection for IFlow
func (thisPt *cFlow) GetDirection(process common.IProcessInfo) uint32 {
	if process.GetSourceIP().Equal(thisPt.Source) {
		return common.FLOWDIRECTIONSEND
	}
	return common.FLOWDIRECTIONRECIVE
}

//---------------------------------------------------------------------------------------

//UpdateStat for IFlow
func (thisPt *cFlow) UpdateStat(process common.IProcessInfo) {
	direction := thisPt.GetDirection(process)
	if direction == common.FLOWDIRECTIONSEND {
		thisPt.Stat.SendByte += uint64(process.GetUsedSize())
		thisPt.Stat.SendPacket++
	} else {
		thisPt.Stat.ReceiveByte += uint64(process.GetUsedSize())
		thisPt.Stat.ReceivePacket++
	}
}

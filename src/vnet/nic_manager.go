package vnet

import (
	"goconnect/common"
	"log"
	"sync"
)

//---------------------------------------------------------------------------------------
type SNICManagerInitparams struct {
	RouterV4  common.IRouter
	RouterV6  common.IRouter
	Commander common.ICommander
}

//---------------------------------------------------------------------------------------

//cNICManager ...
type cNICManager struct {
	nicMap map[uint64]common.INIC
	lock   sync.RWMutex
	params SNICManagerInitparams
}

//---------------------------------------------------------------------------------------

//RegisterNIC for INICManager

func (thisPt *cNICManager) RegisterNIC(nic common.INIC) {
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	//add nic
	if _, fnd := thisPt.nicMap[nic.GetID()]; fnd == false {
		thisPt.nicMap[nic.GetID()] = nic
	} else {
		log.Printf("duplicate NIC registration \n")
		return
	}

	//register routes
	for _, r := range nic.GetRoutes() {
		if len(r.IP) == 4 {
			thisPt.params.RouterV4.RegisterRoute(r, nic.GetID(), nic.GetName(), common.ROUTEMETRICCONNECTED)
		} else {
			thisPt.params.RouterV6.RegisterRoute(r, nic.GetID(), nic.GetName(), common.ROUTEMETRICCONNECTED)
		}
	}

}

//---------------------------------------------------------------------------------------

//GetNICName for INICManager

func (thisPt *cNICManager) GetNICName(id uint64) string {
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	nic := thisPt.nicMap[id]
	if nic == nil {
		return ""
	}
	return nic.GetName()
}

//---------------------------------------------------------------------------------------

//RemoveNIC for INICManager

func (thisPt *cNICManager) RemoveNIC(id uint64) {
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	nic := thisPt.nicMap[id]
	if nic == nil {
		return
	}

	//remove related routes
	for _, r := range nic.GetRoutes() {
		if len(r.IP) == 4 {
			thisPt.params.RouterV4.RemoveRoute(r, nic.GetID())
		} else {
			thisPt.params.RouterV6.RemoveRoute(r, nic.GetID())
		}
	}

	delete(thisPt.nicMap, id)

}

//---------------------------------------------------------------------------------------

//WriteData for INICManager

func (thisPt *cNICManager) WriteData(id uint64, data common.IProcessInfo) {
	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	nic := thisPt.nicMap[id]

	if nic != nil {
		nic.WriteData(data)
	}

}

//---------------------------------------------------------------------------------------

//Flush for INICManager

func (thisPt *cNICManager) Flush() {
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	//terminate all the interfaces
	for _, v := range thisPt.nicMap {
		v.End()
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *cNICManager) Init(params SNICManagerInitparams) {
	thisPt.params = params
	thisPt.nicMap = make(map[uint64]common.INIC)
}

package policy

import (
	"bytes"
	"goconnect/common"
	"net"
)

type cPolicyObjectRange struct {
	cPolicyObjectBase
	Start        string `json:"start" validate:"ip"`
	End          string `json:"end" validate:"ip"`
	startIpCache net.IP
	endIpCache   net.IP
}

//---------------------------------------------------------------------------------------

func (thisPt *cPolicyObjectRange) Match(packet common.IProcessInfo, side uint32) bool {

	//check for cache
	if thisPt.startIpCache == nil {
		thisPt.startIpCache = net.ParseIP(thisPt.Start)
		thisPt.endIpCache = net.ParseIP(thisPt.End)
		if v4 := thisPt.startIpCache.To4(); v4 != nil {
			thisPt.startIpCache = v4
			thisPt.endIpCache = thisPt.endIpCache.To4()
		}
	}

	//
	var ipObj net.IP
	if side == ObjectMatchSideDestination {
		ipObj = packet.GetDestinationIP()
	} else {
		ipObj = packet.GetSourceIP()
	}

	// compare
	if bytes.Compare(ipObj, thisPt.startIpCache) >= 0 && bytes.Compare(ipObj, thisPt.endIpCache) <= 0 {
		return true
	}
	return false
}

//---------------------------------------------------------------------------------------
//override
func (thisPt *cPolicyObjectRange) Init(pMan iPolicyObjectManager, base *cPolicyObjectBase, util common.IUtils) error {
	thisPt.LoadBase(pMan, base, util, ObjectPositionl3Address)
	return util.ValidateStruct(*thisPt)
}

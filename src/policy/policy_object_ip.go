package policy

import (
	"goconnect/common"
	"net"
)

type cPolicyObjectIP struct {
	cPolicyObjectBase
	IP      string `json:"ip" validate:"cidr"`
	ipCache *net.IPNet
}

//---------------------------------------------------------------------------------------

func (thisPt *cPolicyObjectIP) Match(packet common.IProcessInfo, side uint32) bool {

	//check for cache
	if thisPt.ipCache == nil {
		_, thisPt.ipCache, _ = net.ParseCIDR(thisPt.IP)
	}

	var ipObj net.IP
	if side == ObjectMatchSideDestination {
		ipObj = packet.GetDestinationIP()
	} else {
		ipObj = packet.GetSourceIP()
	}

	return thisPt.ipCache.Contains(ipObj)
}

//---------------------------------------------------------------------------------------
//override
func (thisPt *cPolicyObjectIP) Init(pMan iPolicyObjectManager, base *cPolicyObjectBase, util common.IUtils) error {
	thisPt.LoadBase(pMan, base, util, ObjectPositionl3Address)
	return util.ValidateStruct(*thisPt)
}

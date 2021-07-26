package policy

import (
	"goconnect/common"
)

type cPolicyObjectSch struct {
	cPolicyObjectBase
	Day        string `json:"day" validate:"omitempty,day"`
	StartTimes string `json:"start_time" validate:"time"`
	EndTime    string `json:"end_time" validate:"time"`
}

//---------------------------------------------------------------------------------------

func (thisPt *cPolicyObjectSch) Match(packet common.IProcessInfo, side uint32) bool {
	return false
}

//---------------------------------------------------------------------------------------
//override
func (thisPt *cPolicyObjectSch) Init(pMan iPolicyObjectManager, base *cPolicyObjectBase, util common.IUtils) error {
	thisPt.LoadBase(pMan, base, util, ObjectPositionSch)
	return util.ValidateStruct(*thisPt)
}

package policy

import "goconnect/common"

//---------------------------------------------------------------------------------------

type cPolicyObjectBase struct {
	Name      string `json:"name" validate:"name"`
	Type      string
	position  uint32
	policyMan iPolicyObjectManager
}

//---------------------------------------------------------------------------------------

// GetType for iPolicyMatchObject
func (thisPt *cPolicyObjectBase) GetType() string {
	return thisPt.Type
}

//---------------------------------------------------------------------------------------

// GetName for iPolicyMatchObject
func (thisPt *cPolicyObjectBase) GetName() string {
	return thisPt.Name
}

//---------------------------------------------------------------------------------------
// GetName for iPolicyMatchObject
func (thisPt *cPolicyObjectBase) GetPosition() uint32 {
	return thisPt.position
}

//---------------------------------------------------------------------------------------

func (thisPt *cPolicyObjectBase) PostLoad() bool {
	return true
}

//---------------------------------------------------------------------------------------

func (thisPt *cPolicyObjectBase) LoadBase(pMan iPolicyObjectManager, base *cPolicyObjectBase, util common.IUtils, position uint32) {
	thisPt.policyMan = pMan
	thisPt.position = position
	thisPt.Name = base.Name
	thisPt.Type = base.Type
}

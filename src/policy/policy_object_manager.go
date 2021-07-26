package policy

import (
	"errors"
	"goconnect/common"
	"sync"
)

//---------------------------------------------------------------------------------------
const (
	ObjectTypeIP    = "ip"
	ObjectTypeRange = "range"
	ObjectTypeSch   = "schedule"
)

//---------------------------------------------------------------------------------------
const (
	ObjectPositionl3Address  = 0
	ObjectPositionl3Protocol = 1
	ObjectPositionl4Address  = 3
	ObjectPositionl4Protocol = 4
	ObjectPositionLatLong    = 6
	ObjectPositionCountry    = 7
	ObjectPositionAS         = 8
	ObjectPositionUser       = 9
	ObjectPositionGroup      = 10
	ObjectPositionSch        = 11
)

//---------------------------------------------------------------------------------------
const (
	ObjectMatchSideSource      = 0
	ObjectMatchSideDestination = 1
)

//---------------------------------------------------------------------------------------
type iPolicyObject interface {
	Match(packet common.IProcessInfo, side uint32) bool
	PostLoad() bool
	GetType() string
	GetPosition() uint32
	GetName() string
}

//---------------------------------------------------------------------------------------
type iPolicyObjectManager interface {
	GetObject(name string) iPolicyObject
}

//---------------------------------------------------------------------------------------
type sPolicyObjectManagerParams struct {
	config common.IDynamicConfigManager
	utils  common.IUtils
}

//---------------------------------------------------------------------------------------

type cPolicyObjectManager struct {
	objects map[string]iPolicyObject
	lock    sync.RWMutex
	params  sPolicyObjectManagerParams
}

//---------------------------------------------------------------------------------------
func (thisPt *cPolicyObjectManager) loadObject(jobject interface{}, tobject interface{}) error {

	//cast json bject
	if err := thisPt.params.utils.CastJsonObject(jobject, tobject); err != nil {
		return err
	}
	return nil
}

//---------------------------------------------------------------------------------------

//OnCommand for iPolicyObjectManager
func (thisPt *cPolicyObjectManager) GetObject(name string) iPolicyObject {
	//It is an unprotected call. so this function should always be called in the context of other protected functions
	if obj, fnd := thisPt.objects[name]; fnd {
		return obj
	}
	return nil
}

//---------------------------------------------------------------------------------------

//OnCommand for IDynamicConfigActor
func (thisPt *cPolicyObjectManager) OnCommand(section string, params interface{}) error {
	objectList := params.([]interface{})
	tempMap := make(map[string]iPolicyObject)

	//
	for _, objectInfo := range objectList {
		var iobj iPolicyObject
		baseInfo := cPolicyObjectBase{}

		//load object
		if err := thisPt.loadObject(objectInfo, &baseInfo); err != nil {
			return err
		}

		//check object type
		if baseInfo.GetType() == ObjectTypeIP { // IP object
			obj := &cPolicyObjectIP{}

			if err := thisPt.loadObject(objectInfo, obj); err != nil {
				return err
			}

			if err := obj.Init(thisPt, &baseInfo, thisPt.params.utils); err != nil {
				return err
			}

			iobj = obj
		} else if baseInfo.GetType() == ObjectTypeRange { //range object
			obj := &cPolicyObjectRange{}

			if err := thisPt.loadObject(objectInfo, obj); err != nil {
				return err
			}

			if err := obj.Init(thisPt, &baseInfo, thisPt.params.utils); err != nil {
				return err
			}
			iobj = obj
		} else if baseInfo.GetType() == ObjectTypeSch { //schedule object
			obj := &cPolicyObjectSch{}

			if err := thisPt.loadObject(objectInfo, obj); err != nil {
				return err
			}

			if err := obj.Init(thisPt, &baseInfo, thisPt.params.utils); err != nil {
				return err
			}
			iobj = obj
		} else { // base object
			return errors.New("invalid object type " + baseInfo.Type)
		}

		//add object to the temporary map
		if _, b := tempMap[iobj.GetName()]; b {
			return errors.New("duplicate object name " + iobj.GetName())
		}

		//check for duplicate objects name
		tempMap[iobj.GetName()] = iobj
	}

	//Everything seems good, swap the map
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	thisPt.objects = tempMap

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cPolicyObjectManager) Match(objectName string, processInfo common.IProcessInfo, side uint32) bool {
	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	if object := thisPt.objects[objectName]; object != nil {
		return object.Match(processInfo, side)
	}
	return false
}

//---------------------------------------------------------------------------------------

//OnCommand for IDynamicConfigActor
func (thisPt *cPolicyObjectManager) Init(params sPolicyObjectManagerParams) {
	thisPt.params = params
	thisPt.params.config.RegisterActor("objects", nil, thisPt)
	thisPt.objects = make(map[string]iPolicyObject)
}

//---------------------------------------------------------------------------------------

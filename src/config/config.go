package config

import (
	"encoding/json"
	"goconnect/common"
	"reflect"
	"sync"
)

//---------------------------------------------------------------------------------------
type sDynamicConfigManagerActorInfo struct {
	actor common.IDynamicConfigActor
	param interface{}
}

//---------------------------------------------------------------------------------------

type cDynamicConfigManager struct {
	lock        sync.RWMutex
	configParts map[string]sDynamicConfigManagerActorInfo
	utils       common.IUtils
}

//---------------------------------------------------------------------------------------
func (thisPt *cDynamicConfigManager) handleSegment(segment string, segmentData interface{}) error {

	//find actor
	info, fnd := thisPt.configParts[segment]
	if !fnd {
		return nil
	}

	if info.param != nil {
		//unmarshal data
		nObject := reflect.New(reflect.TypeOf(info.param)).Elem()

		if err := thisPt.utils.CastJsonObject(segmentData, nObject.Addr().Interface()); err != nil {
			return err
		}

		//validate
		if err := thisPt.utils.ValidateStruct(nObject.Interface()); err != nil {
			return err
		}

		return info.actor.OnCommand(segment, nObject.Addr().Interface())
	}

	return info.actor.OnCommand(segment, segmentData)
}

//---------------------------------------------------------------------------------------

//RegisterActor for IDynamicConfigManager
func (thisPt *cDynamicConfigManager) RegisterActor(segment string, param interface{}, actor common.IDynamicConfigActor) {
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()
	thisPt.configParts[segment] = sDynamicConfigManagerActorInfo{actor: actor, param: param}
}

//---------------------------------------------------------------------------------------

//LoadConfigs for IDynamicConfigManager
func (thisPt *cDynamicConfigManager) LoadConfig(configuration string) error {

	configs := make(map[string]interface{})

	//unmarshal
	if err := json.Unmarshal([]byte(configuration), &configs); err != nil {
		return err
	}

	//check for segments
	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	for k, v := range configs {
		if err := thisPt.handleSegment(k, v); err != nil {
			return err
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cDynamicConfigManager) LoadFile(fileName string) error {

	//file name
	data, err := thisPt.utils.LoadJsonFile(fileName)
	if err != nil {
		return err
	}

	//load configuration
	return thisPt.LoadConfig(data)
}

//---------------------------------------------------------------------------------------

func (thisPt *cDynamicConfigManager) Init(util common.IUtils) {
	thisPt.utils = util
	thisPt.configParts = make(map[string]sDynamicConfigManagerActorInfo)
}

//---------------------------------------------------------------------------------------

func Create(util common.IUtils) common.IDynamicConfigManager {
	obj := &cDynamicConfigManager{}
	obj.Init(util)
	return obj
}

//---------------------------------------------------------------------------------------

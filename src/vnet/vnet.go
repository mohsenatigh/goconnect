package vnet

import (
	"goconnect/common"
)

//---------------------------------------------------------------------------------------

//CreateProcessFactory ...
func CreateProcessFactory() common.IProcessFactory {
	return new(cProcessFactory)
}

//---------------------------------------------------------------------------------------

//CreateRouter ...
func CreateRouter(param SRouteParams) common.IRouter {
	router := new(cRouter)
	router.Init(param)
	return router
}

//---------------------------------------------------------------------------------------

//CreateNICManager ...
func CreateNICManager(params SNICManagerInitparams) common.INICManager {
	nicMan := new(cNICManager)
	nicMan.Init(params)
	return nicMan
}

//---------------------------------------------------------------------------------------

//CreateFlowManager ...
func CreateFlowManager(params SFlowManagerInitParams) common.IFlowManager {
	flowMan := new(cFlowManager)
	flowMan.Init(params)
	return flowMan
}

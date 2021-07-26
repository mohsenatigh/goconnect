package commander

import (
	"errors"
	"goconnect/common"
	"net/http"
	"sync"
)

//---------------------------------------------------------------------------------------
type sCommandSelectorAPIInfo struct {
	actor  common.TCommanderSelectorActor
	params interface{}
}

//---------------------------------------------------------------------------------------
type cCommanderSelector struct {
	commands  map[string]sCommandSelectorAPIInfo
	lock      sync.RWMutex
	commander common.ICommander
}

//---------------------------------------------------------------------------------------

//Register for ICommanderSelector
func (thisPt *cCommanderSelector) Register(api string, actor common.TCommanderSelectorActor, params interface{}) {
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	thisPt.commands[api] = sCommandSelectorAPIInfo{actor: actor, params: params}
	thisPt.commander.RegisterCommand(api, params, thisPt)
}

//---------------------------------------------------------------------------------------

//OnCommand for ICommanderActor
func (thisPt *cCommanderSelector) OnCommand(api string, req *http.Request, params interface{}) (common.IHTTPResponse, error) {
	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	info, fnd := thisPt.commands[api]
	if fnd == false {
		return nil, errors.New("invalid API")
	}
	return info.actor(req, params)
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommanderSelector) Init(commander common.ICommander) {
	thisPt.commands = make(map[string]sCommandSelectorAPIInfo)
	thisPt.commander = commander
}

//---------------------------------------------------------------------------------------

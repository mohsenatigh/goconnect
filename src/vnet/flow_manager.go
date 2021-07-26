package vnet

import (
	"goconnect/common"
	"log"
	"net"
	"net/http"
)

//---------------------------------------------------------------------------------------

type sFlowManagerCommandSearchParams struct {
	SrcIP    string `help:"Flow source IP" schema:"src_ip" validate:"omitempty,cidr"`
	DstIP    string `help:"Flow destination IP" schema:"dst_ip" validate:"omitempty,cidr"`
	ID       uint64 `help:"Flow ID" schema:"id" validate:"omitempty,numeric"`
	Sort     string `help:"Sort field, one of [total|send|receive|total_p|send_p|receive_p]. total by default" schema:"sort" validate:"omitempty,min=2,max=64,alphanum"`
	srcIPObj *net.IPNet
	dstIPObj *net.IPNet
}

//---------------------------------------------------------------------------------------

//SFlowManagerInitParams ...
type SFlowManagerInitParams struct {
	Util               common.IUtils
	Commander          common.ICommander
	NicManager         common.INICManager
	SegmentCount       uint32
	MaxLifeTime        uint32
	MaxActiveFlowCount uint32
}

//---------------------------------------------------------------------------------------

//cFlowManager ...
type cFlowManager struct {
	flowTable common.IHashLinkList
	params    SFlowManagerInitParams
	stat      common.STransferStat
}

//---------------------------------------------------------------------------------------

func (thisPt *cFlowManager) matchFlow(flow common.IFlow, param *sFlowManagerCommandSearchParams) bool {

	if param.srcIPObj != nil && !param.srcIPObj.Contains(flow.GetSource()) {
		return false
	}

	if param.dstIPObj != nil && !param.dstIPObj.Contains(flow.GetDestinatin()) {
		return false
	}

	if param.ID > 0 && flow.GetID() != param.ID {
		return false
	}

	return true
}

//---------------------------------------------------------------------------------------

func (thisPt *cFlowManager) prepareSearchParam(params interface{}) *sFlowManagerCommandSearchParams {
	searchParam := params.(*sFlowManagerCommandSearchParams)

	_, searchParam.srcIPObj, _ = net.ParseCIDR(searchParam.SrcIP)
	_, searchParam.dstIPObj, _ = net.ParseCIDR(searchParam.DstIP)

	return searchParam
}

//---------------------------------------------------------------------------------------

func (thisPt *cFlowManager) OnDCCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {

	//
	searchParam := thisPt.prepareSearchParam(params)
	thisPt.flowTable.Iterate(func(object interface{}) bool {
		flow := object.(*cFlow)
		if thisPt.matchFlow(flow, searchParam) {
			flow.Blocked = true
		}
		return true
	})

	return thisPt.params.Util.CreateHttpResponseFromString("OK")
}

//---------------------------------------------------------------------------------------

func (thisPt *cFlowManager) OnStatusCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {
	type sFlowStatus struct {
		FlowCount       uint32               `json:"flow_count"`
		MaxFlowCount    uint32               `json:"max_flow_count"`
		MaxFlowLifeTime uint32               `json:"max_flow_life_time"`
		Status          common.STransferStat `json:"total_transfer"`
	}
	flowInfo := sFlowStatus{}
	flowInfo.FlowCount = thisPt.GetFlowCount()
	flowInfo.MaxFlowCount = thisPt.params.MaxActiveFlowCount
	flowInfo.MaxFlowLifeTime = thisPt.params.MaxLifeTime
	flowInfo.Status = thisPt.stat

	return thisPt.params.Util.CreateHttpResponseFromObject(flowInfo)
}

//---------------------------------------------------------------------------------------

func (thisPt *cFlowManager) OnListCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {

	searchParam := thisPt.prepareSearchParam(params)

	//sort function
	sortCallBack := func(key string, item interface{}) uint64 {
		flow := item.(common.IFlow)
		return flow.GetStat().GetValue(key)
	}

	//create sorter
	sorter := thisPt.params.Util.CreateHeapSorter(common.MAXCOMMANDRESPONSEITEMS, sortCallBack, searchParam.Sort)

	//get items
	thisPt.flowTable.Iterate(func(object interface{}) bool {
		flow := object.(common.IFlow)
		if thisPt.matchFlow(flow, searchParam) {
			sorter.AddItem(flow)
		}
		return true
	})
	return thisPt.params.Util.CreateHttpResponseFromString(sorter.ToJson())
}

//---------------------------------------------------------------------------------------

//GetFlow for IFlowManager
func (thisPt *cFlowManager) GetFlow(process common.IProcessInfo) common.IFlow {

	var flow *cFlow

	//check for remove timeout
	defer func() {
		if flow != nil {

			//update flow stat
			flow.UpdateStat(process)

			//update total send and receive
			if flow.GetDirection(process) == common.FLOWDIRECTIONSEND {
				thisPt.stat.SendByte += uint64(process.GetUsedSize())
				thisPt.stat.SendPacket++
			} else {
				thisPt.stat.ReceiveByte += uint64(process.GetUsedSize())
				thisPt.stat.ReceivePacket++
			}
		}
		thisPt.flowTable.CheckForTimeOut(nil, nil, 0)
	}()

	if flowInt := thisPt.flowTable.Find(process.GetFlowKey(), nil, nil); flowInt != nil {
		return flowInt.(*cFlow)
	}

	//check for max flow count
	if thisPt.flowTable.GetItemsCount() > thisPt.params.MaxActiveFlowCount {
		log.Printf("maximum active flow limit reached (%d). can not create new flow \n", thisPt.params.MaxActiveFlowCount)
		return nil
	}

	flow = new(cFlow)
	flow.Id = process.GetFlowKey()
	flow.Destination = process.GetDestinationIP()
	flow.Source = process.GetSourceIP()
	flow.InNIC = process.GetInNIC()
	flow.netManager = thisPt.params.NicManager
	flow.InNICName = thisPt.params.NicManager.GetNICName(flow.InNIC)
	thisPt.flowTable.Add(process.GetFlowKey(), flow)
	return flow
}

//---------------------------------------------------------------------------------------

//GetFlow for IFlowManager
func (thisPt *cFlowManager) GetFlowCount() uint32 {
	return thisPt.flowTable.GetItemsCount()
}

//---------------------------------------------------------------------------------------

//
func (thisPt *cFlowManager) Init(params SFlowManagerInitParams) {
	thisPt.params = params
	thisPt.flowTable = params.Util.CreateHashLinkList(params.SegmentCount, uint64(params.MaxLifeTime))
	if thisPt.flowTable == nil {
		log.Fatalf("can not create flow table \n")
	}

	//register api
	selector := thisPt.params.Commander.CreateSelector()
	selector.Register("flows_list", thisPt.OnListCommand, sFlowManagerCommandSearchParams{})
	selector.Register("flows_dc", thisPt.OnDCCommand, sFlowManagerCommandSearchParams{})
	selector.Register("flows_status", thisPt.OnStatusCommand, nil)
}

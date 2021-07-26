package vnet

import (
	"fmt"
	"goconnect/common"
	"log"
	"net"
	"net/http"
	"sync"
)

//---------------------------------------------------------------------------------------

type SRouteParams struct {
	Util      common.IUtils
	Version   int
	Commander common.ICommander
}

//---------------------------------------------------------------------------------------

type sRouteInfo struct {
	Nic        uint64 `json:"nic_id"`
	MatchCount uint64 `json:"match_count"`
	Metric     uint32 `json:"metric"`
	NicName    string `json:"nic_name"`
}

//---------------------------------------------------------------------------------------

//sRoute ...
type sRoutes struct {
	Network common.SIPNet `json:"network"`
	Routes  []sRouteInfo  `json:"routes"`
}

//---------------------------------------------------------------------------------------

//cRouter ...
type cRouter struct {
	routes       common.IIPTrie
	defaultRoute sRoutes
	lock         sync.RWMutex
	params       SRouteParams
}

//---------------------------------------------------------------------------------------
func (thisPt *cRouter) OnListCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {

	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	routeList := []*sRoutes{}
	itFunc := func(data interface{}) {
		routes := data.(*sRoutes)
		routeList = append(routeList, routes)
	}
	thisPt.routes.Iterate(itFunc)

	//add default routes
	if len(thisPt.defaultRoute.Routes) > 0 {
		routeList = append(routeList, &thisPt.defaultRoute)
	}

	return thisPt.params.Util.CreateHttpResponseFromObject(routeList)
}

//---------------------------------------------------------------------------------------

//RegisterRoute for IRoute

func (thisPt *cRouter) RegisterRoute(network net.IPNet, nicID uint64, nicName string, metric uint32) {

	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	iMask, _ := network.Mask.Size()

	var route *sRoutes

	//first try to find existing routes
	if iMask == 0 {
		route = &thisPt.defaultRoute
	} else if res := thisPt.routes.SearchExact(network.IP, uint32(iMask)); res == nil {
		route = new(sRoutes)
		route.Network = common.SIPNet(network)
		thisPt.routes.Add(network.IP, uint32(iMask), route)
	} else {
		route = res.(*sRoutes)
	}

	//check for duplicate
	for _, rInfo := range route.Routes {
		if rInfo.Nic == nicID {
			log.Printf("duplicate route registration \n")
			return
		}
	}

	routeInfo := sRouteInfo{}
	routeInfo.MatchCount = 0
	routeInfo.Metric = metric
	routeInfo.Nic = nicID
	routeInfo.NicName = nicName
	route.Routes = append(route.Routes, routeInfo)
}

//---------------------------------------------------------------------------------------

//RemoveRoute for IRoute

func (thisPt *cRouter) RemoveRoute(network net.IPNet, nicID uint64) {

	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	iMask, _ := network.Mask.Size()
	res := thisPt.routes.SearchExact(network.IP, uint32(iMask))

	if res == nil {
		return
	}

	route := res.(*sRoutes)

	//find route info
	for index, rInfo := range route.Routes {
		if rInfo.Nic == nicID {
			route.Routes = append(route.Routes[:index], route.Routes[index+1:]...)
			break
		}
	}

	if len(route.Routes) == 0 {
		thisPt.routes.Remove(network.IP, uint32(iMask))
	}

}

//---------------------------------------------------------------------------------------

//GetDestinatin for IRoute

func (thisPt *cRouter) GetDestinatin(ip net.IP) uint64 {

	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	//select
	var routes *sRoutes
	out := thisPt.routes.Search(ip)
	if out == nil {
		routes = &thisPt.defaultRoute
	} else {
		routes = out.(*sRoutes)
	}

	//can not find any destination
	if len(routes.Routes) == 0 {
		return 0
	}

	//selecting the best route based on less metric or lower match count
	bestRoute := &routes.Routes[0]
	for i := 1; i < len(routes.Routes); i++ {
		if routes.Routes[i].Metric < bestRoute.Metric {
			bestRoute = &routes.Routes[i]
		} else if bestRoute.Metric == routes.Routes[i].Metric {
			if bestRoute.MatchCount > routes.Routes[i].MatchCount {
				bestRoute = &routes.Routes[i]
			}
		}
	}

	bestRoute.MatchCount++
	return bestRoute.Nic
}

//---------------------------------------------------------------------------------------

//Init
func (thisPt *cRouter) Init(params SRouteParams) {

	//
	thisPt.routes = params.Util.CreateNewIPTrie(params.Version)
	thisPt.params = params

	//
	selector := thisPt.params.Commander.CreateSelector()
	selector.Register(fmt.Sprintf("routes%d_list", params.Version), thisPt.OnListCommand, nil)
}

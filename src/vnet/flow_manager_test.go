package vnet

import (
	"goconnect/common"
	"goconnect/utils"
	"log"
	"testing"
	"time"
)

func TestFlowManager(t *testing.T) {

	packetFactory := CreateProcessFactory()

	//check send packet
	sendPacket := packetFactory.CreateProcessInfoByName("dns_reqv4")
	receivePacket := packetFactory.CreateProcessInfoByName("dns_resv4")

	log.Printf("send %v \n", sendPacket)
	log.Printf("receive %v \n", receivePacket)

	//
	params := SFlowManagerInitParams{}

	params.MaxActiveFlowCount = 64
	params.Util = utils.Create()
	params.SegmentCount = 64
	params.MaxLifeTime = 100

	flowMan := cFlowManager{}
	flowMan.Init(params)

	//simple test
	flow := flowMan.GetFlow(sendPacket)
	if flow == nil {
		log.Fatalf("can not create flow\n")
	}

	//check direction
	if flow.GetDirection(sendPacket) != common.FLOWDIRECTIONSEND {
		log.Fatalf("invalid direction\n")
	}

	//check recive
	flow = flowMan.GetFlow(receivePacket)
	if flow == nil {
		log.Fatalf("can not create flow\n")
	}

	//check receive
	if flow.GetDirection(receivePacket) != common.FLOWDIRECTIONRECIVE {
		log.Fatalf("invalid direction\n")
	}

	//check for remove
	for i := 0; i < int(params.SegmentCount); i++ {
		flowMan.flowTable.CheckForTimeOut(nil, nil, time.Now().Unix()+110)
	}

	//check for count
	if flowMan.GetFlowCount() != 0 {
		log.Fatalf("remove check failed\n")
	}

	for i := 0; i < int(params.MaxActiveFlowCount)+1; i++ {
		packet := packetFactory.CreateRandomProcessInfoByName("dns_reqv4")
		if flowMan.GetFlow(packet) == nil {
			log.Fatalf("can not create flow\n")
		}
	}

	//check for max flow count
	packet := packetFactory.CreateRandomProcessInfoByName("dns_reqv4")
	if flowMan.GetFlow(packet) != nil {
		log.Fatalf("flow limit check failed\n")
	}
}

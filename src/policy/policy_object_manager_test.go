package policy

import (
	"goconnect/config"
	"goconnect/utils"
	"goconnect/vnet"
	"testing"
)

//---------------------------------------------------------------------------------------
func TestObjectManager(t *testing.T) {
	objectsJsons :=
		`
{
	"objects" : 
	[
		{
			"type":"ip",
			"name":"test_ip1",
			"ip":"192.168.1.200/32"
		},
		{
			"type":"ip",
			"name":"test_ip2",
			"ip":"8.8.8.8/32"
		},
		{
			"type":"ip",
			"name":"test_ip3",
			"ip":"192.168.1.0/24"
		},
		{
			"type":"ip",
			"name":"test_ip4",
			"ip":"8.8.8.4/32"
		},
		{
			"type":"range",
			"name":"test_range",
			"start":"192.168.1.1",
			"end":"192.168.1.201"
		},
		{
			"type":"range",
			"name":"test_range2",
			"start":"192.168.1.1",
			"end":"192.168.1.100"
		},
		{
			"type":"schedule",
			"name":"sch1",
			"day" : "sat",
			"start_time" : "12:00",
			"end_time" : "12:10",
		},
		{
			"type":"schedule2",
			"name":"sch2",
			"start_time" : "00:00",
			"end_time" : "23:59",
		},
	]
}
`
	//create object manager
	params := sPolicyObjectManagerParams{}
	params.utils = utils.Create()
	params.config = config.Create(params.utils)

	objetMan := &cPolicyObjectManager{}
	objetMan.Init(params)

	//load sample configs
	if err := params.config.LoadConfig(objectsJsons); err != nil {
		t.Fatal(err)
	}

	//create dummy process info
	processFactory := vnet.CreateProcessFactory()
	pInfo := processFactory.CreateProcessInfoByName("dns_reqv4")

	//should match source
	if !objetMan.Match("test_ip1", pInfo, ObjectMatchSideSource) {
		t.Fatal("match failed")
	}

	if !objetMan.Match("test_ip2", pInfo, ObjectMatchSideDestination) {
		t.Fatal("match failed")
	}

	if !objetMan.Match("test_ip3", pInfo, ObjectMatchSideSource) {
		t.Fatal("match failed")
	}

	if objetMan.Match("test_ip4", pInfo, ObjectMatchSideDestination) {
		t.Fatal("match failed")
	}

	if objetMan.Match("invalidname", pInfo, ObjectMatchSideDestination) {
		t.Fatal("match failed")
	}

	if !objetMan.Match("test_range", pInfo, ObjectMatchSideSource) {
		t.Fatal("match failed")
	}

	if objetMan.Match("test_range", pInfo, ObjectMatchSideDestination) {
		t.Fatal("match failed")
	}

	if objetMan.Match("test_range2", pInfo, ObjectMatchSideSource) {
		t.Fatal("match failed")
	}

}

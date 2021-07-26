package vnet

import (
	"goconnect/utils"
	"net"
	"testing"
)

func TestRouter(t *testing.T) {
	router := cRouter{}

	params := SRouteParams{}
	params.Util = utils.Create()
	params.Version = 4

	router.Init(params)

	_, inet, _ := net.ParseCIDR("192.168.1.0/24")
	testIP := net.ParseIP("192.168.1.1")
	//simple test
	router.RegisterRoute(*inet, 1, "test", 10)
	if router.GetDestinatin(testIP) != 1 {
		t.Fatalf("simple search failed \n")
	}

	//check for best route
	router.RegisterRoute(*inet, 2, "test", 1)
	if router.GetDestinatin(testIP) != 2 {
		t.Fatalf("best route failed \n")
	}

	//remove best
	router.RemoveRoute(*inet, 2)
	if router.GetDestinatin(testIP) != 1 {
		t.Fatalf("best route failed \n")
	}

	//remove all
	router.RemoveRoute(*inet, 1)
	if router.GetDestinatin(testIP) != 0 {
		t.Fatalf("best route failed \n")
	}

	//check for load balancing
	router.RegisterRoute(*inet, 2, "test", 1)
	router.RegisterRoute(*inet, 1, "test", 1)
	if router.GetDestinatin(testIP) == router.GetDestinatin(testIP) {
		t.Fatalf("load balancing failed\n")
	}

	//
	_, inet2, _ := net.ParseCIDR("192.168.1.1/32")
	router.RegisterRoute(*inet, 2, "test", 1)
	router.RegisterRoute(*inet2, 3, "test", 1)
	if router.GetDestinatin(testIP) != 3 {
		t.Fatalf("load balancing failed\n")
	}

	t.Log("successfully test Router \n")
}

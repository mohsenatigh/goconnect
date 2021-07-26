package protocols

import (
	"goconnect/utils"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestTun(t *testing.T) {

	params := STunInitParams{}
	params.Utils = utils.Create()
	params.Name = "testtun"
	params.Mtu = 1400
	params.IPList = append(params.IPList, "172.16.0.1/24")

	tun := cTun{}

	if tun.Init(params) != nil {
		t.Fatalf("can not init tun device \n")
	}

	_, err := netlink.LinkByName(params.Name)
	if err != nil {
		t.Fatalf("can not create tun device \n")
	}
}

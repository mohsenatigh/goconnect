package utils

import (
	"net"
	"testing"
)

func TestIPPool(t *testing.T) {
	ipPool := cIPPool{}

	needCnt := 65534
	cnt := ipPool.Init("192.168.0.0", "192.168.255.255")
	if cnt != needCnt {
		t.Fatal("ip pool test failed \n")
	}

	//allocate all IP address
	ipList := make([]net.IP, needCnt)
	for i := 0; i < needCnt; i++ {
		res, ip := ipPool.AllocateIP()
		if res == false {
			t.Fatal("ip reservation failed \n")
		}
		ipList[i] = ip
	}

	if len(ipPool.ipList) != 0 {
		t.Fatal("ip pool must be empty \n")
	}

	//relese all IP address
	for i := 0; i < needCnt; i++ {
		ipPool.FreeIP(ipList[i])
	}

	if len(ipPool.ipList) != needCnt {
		t.Fatal("ip pool must be full \n")
	}

	t.Log("successfully test cIPPool \n")
}

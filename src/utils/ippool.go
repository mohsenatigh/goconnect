package utils

import (
	"bytes"
	"log"
	"net"
	"sync"
)

//
type cIPPool struct {
	listLock sync.Mutex //access lock
	ipList   []net.IP   //IP pool list
	ipv4     bool
}

//---------------------------------------------------------------------------------------

func (thisPt *cIPPool) getNextIP(ip *net.IP) net.IP {
	bArr := make([]byte, 16)
	copy(bArr, *ip)
	len := 15
	for i := len; i >= 0; i-- {
		bArr[i]++
		if bArr[i] != 0 {
			break
		}
	}

	ipOut := net.IP(bArr)
	return ipOut
}

//---------------------------------------------------------------------------------------

//AllocateIP for IIPPool
func (thisPt *cIPPool) AllocateIP() (bool, net.IP) {
	thisPt.listLock.Lock()
	defer thisPt.listLock.Unlock()

	if len(thisPt.ipList) == 0 {
		return false, nil
	}

	ip := thisPt.ipList[0]
	thisPt.ipList = thisPt.ipList[1:]
	return true, ip
}

//---------------------------------------------------------------------------------------

//FreeIP for IIPPool
func (thisPt *cIPPool) FreeIP(ip net.IP) {
	thisPt.listLock.Lock()
	defer thisPt.listLock.Unlock()
	thisPt.ipList = append(thisPt.ipList, ip)
}

//---------------------------------------------------------------------------------------

//Init for IIPPool
func (thisPt *cIPPool) Init(start string, end string) int {
	const maxIPPoolLength = 512000
	startIP := net.ParseIP(start)
	endIP := net.ParseIP(end)

	//
	if startIP.IsUnspecified() || endIP.IsUnspecified() {
		log.Printf("invalid ip pool range address %s %s \n", start, end)
		return 0
	}

	if bytes.Compare(startIP, endIP) != -1 {
		log.Printf("invalid ip pool range address %s %s \n", start, end)
		return 0
	}

	//check version
	thisPt.ipv4 = (endIP.To4() != nil)

	//add ips
	i := 0
	nIP := startIP
	for i = 0; i < maxIPPoolLength; i++ {
		nIP = thisPt.getNextIP(&nIP)
		if bytes.Compare(nIP, endIP) == 0 {
			break
		}

		adIp := nIP
		if thisPt.ipv4 {
			adIp = adIp.To4()
		}
		thisPt.ipList = append(thisPt.ipList, adIp)
	}
	return i
}

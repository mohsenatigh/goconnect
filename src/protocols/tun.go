package protocols

import (
	"goconnect/common"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

const tunMAXReadBuffer = 16384

//---------------------------------------------------------------------------------------

//STunInitParams ...
type STunInitParams struct {
	Name           string
	IPList         []string
	Routes         []string
	Mtu            int
	Utils          common.IUtils
	UpScript       []string
	DownScript     []string
	PacketFactory  common.IProcessFactory
	ProtocolActor  common.IProtocolActor
	NetworkManager common.INICManager
}

//---------------------------------------------------------------------------------------

type cTun struct {
	cNICBase
	handle *water.Interface
	params STunInitParams
}

//---------------------------------------------------------------------------------------

//Write override cNICBase.write
func (thisPt *cTun) WriteData(data common.IProcessInfo) {
	thisPt.handle.Write(data.GetBuffer())
	thisPt.UpdateReceive(data)
}

//---------------------------------------------------------------------------------------

func (thisPt *cTun) registerInterface() error {

	//register internally
	thisPt.Id = thisPt.params.Utils.GetUniqID()
	thisPt.Name = "tun"
	thisPt.NicType = common.INICTypeTUN

	for _, r := range thisPt.params.Routes {
		_, netres, err := net.ParseCIDR(r)
		if err != nil {
			return err
		}
		thisPt.Routes = append(thisPt.Routes, *netres)
	}

	//add default routes, If there is not any selective route
	if len(thisPt.Routes) == 0 {
		_, netres, _ := net.ParseCIDR("0.0.0.0/0")
		thisPt.Routes = append(thisPt.Routes, *netres)

		_, netres, _ = net.ParseCIDR("::0/0")
		thisPt.Routes = append(thisPt.Routes, *netres)
	}

	if thisPt.params.NetworkManager != nil {
		thisPt.params.NetworkManager.RegisterNIC(thisPt)
	}

	//OS configuration. Set IP list
	link, err := netlink.LinkByName(thisPt.params.Name)
	if err != nil {
		return err
	}
	for _, add := range thisPt.params.IPList {
		addr, err := netlink.ParseAddr(add)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
	}

	//set MTU and change state
	if err = netlink.LinkSetMTU(link, thisPt.params.Mtu); err != nil {
		return err
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------

func (thisPt *cTun) read() {

	buffer := [tunMAXReadBuffer]byte{}
	for {
		//read packet
		n, err := thisPt.handle.Read(buffer[0:])
		if err != nil {
			log.Printf("can not read from tun device with error %s \n", err.Error())
			time.Sleep(1 * time.Second)
			continue
		}

		if n < 1 {
			continue
		}

		//create packet
		packet := thisPt.params.PacketFactory.CreateProcessInfo(buffer[0:n])
		if packet.ProcessAsNetPacket() == false {
			continue
		}

		packet.SetInNIC(thisPt.Id)
		thisPt.params.ProtocolActor.OnNewPacket(packet)
		thisPt.UpdateSend(packet)
	}

}

//---------------------------------------------------------------------------------------

func (thisPt *cTun) runScript(scripts []string) {
	if len(scripts) == 0 {
		return
	}

	for _, path := range scripts {
		log.Printf("run command { %s } \n", path)
		parts := strings.Split(path, " ")
		_, err := exec.Command(parts[0], parts[1:]...).Output()
		if err != nil {
			log.Println(err)
		}
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *cTun) End() {
	thisPt.runScript(thisPt.params.DownScript)
}

//---------------------------------------------------------------------------------------

func (thisPt *cTun) Init(params STunInitParams) error {

	//
	thisPt.params = params

	//In case of uncontrolled termination. calling down script will act as a cleaner mechanism
	thisPt.runScript(thisPt.params.DownScript)

	//create tap device
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = params.Name
	ifce, err := water.New(config)
	if err != nil {
		return err
	}
	thisPt.handle = ifce

	//
	if err := thisPt.registerInterface(); err != nil {
		return err
	}

	//
	go thisPt.read()

	thisPt.runScript(thisPt.params.UpScript)

	return nil
}

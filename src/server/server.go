package server

import (
	"flag"
	"fmt"
	"goconnect/auth"
	"goconnect/commander"
	"goconnect/common"
	"goconnect/db"
	"goconnect/protocols"
	"goconnect/utils"
	"goconnect/vnet"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

//CServer ...
type CServer struct {
	utils         common.IUtils
	db            common.IDatabase
	authManager   common.IAuthenticationManger
	packetFactory common.IProcessFactory
	routerv4      common.IRouter
	routerv6      common.IRouter
	nicManager    common.INICManager
	flowManager   common.IFlowManager
	ipPool        common.IIPPool
	commander     common.ICommander
	settings      cSettings
}

//---------------------------------------------------------------------------------------

//OnNewPacket ...
func (thisPt *CServer) OnNewPacket(packet common.IProcessInfo) {

	//free packet at the end
	defer func() {
		thisPt.packetFactory.FreeProcessInfo(packet)
	}()

	//check for multicast
	if packet.GetDestinationIP().IsMulticast() {
		return
	}

	//find packet flow
	flow := thisPt.flowManager.GetFlow(packet)
	if flow == nil {
		return
	}

	//check for blocked sessions
	if flow.GetBlocked() {
		return
	}

	//first time routing
	if flow.GetOutNIC() == 0 {
		outNic := uint64(0)
		if packet.GetIPVersion() == 4 {
			outNic = thisPt.routerv4.GetDestinatin(packet.GetDestinationIP())
		} else {
			outNic = thisPt.routerv6.GetDestinatin(packet.GetDestinationIP())
		}

		//can not find any destination
		if outNic == 0 || outNic == packet.GetInNIC() {
			return
		}
		flow.SetOutNIC(outNic)
	}

	//find the packet destination
	dir := flow.GetDirection(packet)
	if dir == common.FLOWDIRECTIONRECIVE {
		thisPt.nicManager.WriteData(flow.GetInNIC(), packet)
		return
	}

	//forward packet
	thisPt.nicManager.WriteData(flow.GetOutNIC(), packet)
}

//---------------------------------------------------------------------------------------
func (thisPt *CServer) initCommander() {

	//fill commander params
	params := commander.SCommanderInitParams{}
	params.Utils = thisPt.utils
	params.Authenticator = thisPt.authManager
	params.BindAddress = thisPt.settings.getSettings().Command.BindAddress
	params.CertFile = thisPt.settings.getSettings().Command.Certificate
	params.KeyFile = thisPt.settings.getSettings().Command.KeyFile
	params.ServeStaticContents = thisPt.settings.getSettings().Command.ServeStaticContents
	params.StaticDataPath = thisPt.settings.getSettings().Command.StaticDataPath
	params.ValidClients = thisPt.settings.getSettings().Command.ValidClients
	params.EnableSeprateManagemnet = thisPt.settings.getSettings().Command.Enable
	params.MaintenanceHook = thisPt.settings.getSettings().Command.MaintenanceHook
	thisPt.commander = commander.Create(params)

	//set authenticator commander
	thisPt.authManager.SetCommander(thisPt.commander)
}

//---------------------------------------------------------------------------------------

func (thisPt *CServer) initDB() {

	//create database object
	thisPt.db = db.Create(thisPt.settings.getSettings().DB.Driver, thisPt.settings.getSettings().DB.Params)
	if thisPt.db == nil {
		log.Fatal("can not create database object")
	}

}

//---------------------------------------------------------------------------------------

func (thisPt *CServer) initAuthenticators() {

	params := auth.SAuthenticationManagerParams{}
	params.Utils = thisPt.utils
	params.Commander = thisPt.commander

	//
	thisPt.authManager = auth.Create(params)

	//check for dummy authenticator
	if thisPt.settings.settings.Authentication.EnableDummyAuth {
		if err := thisPt.authManager.RegisterDummyAuthenticator(thisPt.settings.getSettings().Authentication.DummyAuthConfigPath); err != nil {
			log.Fatalln(err)
		}
	}

}

//---------------------------------------------------------------------------------------

func (thisPt *CServer) initNetworkSubsystems() {

	//
	thisPt.packetFactory = vnet.CreateProcessFactory()

	//
	routerParam := vnet.SRouteParams{}
	routerParam.Util = thisPt.utils
	routerParam.Version = 4
	routerParam.Commander = thisPt.commander
	thisPt.routerv4 = vnet.CreateRouter(routerParam)

	//
	routerParam.Version = 6
	thisPt.routerv6 = vnet.CreateRouter(routerParam)

	//
	nicParams := vnet.SNICManagerInitparams{}
	nicParams.RouterV4 = thisPt.routerv4
	nicParams.RouterV6 = thisPt.routerv6
	nicParams.Commander = thisPt.commander
	thisPt.nicManager = vnet.CreateNICManager(nicParams)

	//
	flowParams := vnet.SFlowManagerInitParams{}
	flowParams.MaxActiveFlowCount = thisPt.settings.settings.FlowManager.MaximumFlowCount
	flowParams.MaxLifeTime = thisPt.settings.settings.FlowManager.InactiveLifeTime
	flowParams.SegmentCount = thisPt.settings.settings.FlowManager.HashSlots
	flowParams.Util = thisPt.utils
	flowParams.NicManager = thisPt.nicManager
	flowParams.Commander = thisPt.commander
	thisPt.flowManager = vnet.CreateFlowManager(flowParams)

	//
	thisPt.ipPool = thisPt.utils.CreateLocalIPPool(thisPt.settings.settings.IPPool.Start, thisPt.settings.settings.IPPool.End)
}

//---------------------------------------------------------------------------------------

func (thisPt *CServer) initProtocols() {

	//check for SSL VPN server
	if thisPt.settings.getSettings().SSLVpn.Enable {
		sslParams := protocols.SSSLVpnInitParams{}
		sslParams.InboundManagemnet = thisPt.settings.getSettings().SSLVpn.InboundManagement
		sslParams.Address = thisPt.settings.getSettings().SSLVpn.ServerAddress
		sslParams.CertFile = thisPt.settings.getSettings().SSLVpn.Certificate
		sslParams.ClientsNetMask = thisPt.settings.getSettings().SSLVpn.NetMask
		sslParams.DPDInterval = uint16(thisPt.settings.getSettings().SSLVpn.DPDInterval)
		sslParams.IdelTimeout = thisPt.settings.getSettings().SSLVpn.IdelTimeout
		sslParams.InactiveSessionsTimeOut = thisPt.settings.getSettings().SSLVpn.InactiveSessionsTimeOut
		sslParams.KeepAlive = thisPt.settings.getSettings().SSLVpn.KeepAliveInterval
		sslParams.KeyFile = thisPt.settings.getSettings().SSLVpn.KeyFile
		sslParams.Mtu = thisPt.settings.getSettings().SSLVpn.Mtu
		sslParams.RekeyInterval = thisPt.settings.getSettings().SSLVpn.RekeyInterval
		sslParams.TunnelDNS = thisPt.settings.getSettings().SSLVpn.TunnelDNS
		sslParams.Debug = thisPt.settings.getSettings().SSLVpn.Debug
		sslParams.DNSServers = thisPt.settings.getSettings().SSLVpn.DNSServers
		sslParams.Utils = thisPt.utils
		sslParams.AuthMan = thisPt.authManager
		sslParams.NetworkManager = thisPt.nicManager
		sslParams.PacketFactory = thisPt.packetFactory
		sslParams.IPPool = thisPt.ipPool
		sslParams.ProtocolActor = thisPt
		sslParams.Command = thisPt.commander
		if thisPt.settings.getSettings().SSLVpn.UseLocalDNSServer {
			sslParams.DNSServers = append(sslParams.DNSServers, thisPt.settings.getSettings().TUN.IPList...)
		}
		protocols.CreateSSLVPN(sslParams)
	}

	//check for TUN device
	if thisPt.settings.getSettings().TUN.Enable {
		tunParams := protocols.STunInitParams{}
		tunParams.Name = thisPt.settings.getSettings().TUN.Name
		tunParams.Mtu = int(thisPt.settings.getSettings().TUN.Mtu)
		tunParams.IPList = thisPt.settings.getSettings().TUN.IPList
		tunParams.Routes = thisPt.settings.getSettings().TUN.Routes
		tunParams.UpScript = thisPt.settings.getSettings().TUN.UpScript
		tunParams.DownScript = thisPt.settings.getSettings().TUN.DownScript
		tunParams.NetworkManager = thisPt.nicManager
		tunParams.PacketFactory = thisPt.packetFactory
		tunParams.Utils = thisPt.utils
		tunParams.ProtocolActor = thisPt
		protocols.CreateTunInterface(tunParams)
	}
}

//---------------------------------------------------------------------------------------

func (thisPt *CServer) initLog() {

	// set default log file
	logFile := thisPt.settings.getSettings().Log.LogFile
	if len(logFile) > 0 {
		if !strings.Contains(logFile, "syslog:") {
			if w, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err == nil {
				log.SetOutput(w)
			} else {
				fmt.Printf("can not open log file with error %s \n", err.Error())
			}
		} else {
			if sysLogParams := strings.SplitN(logFile, ":", 3); len(sysLogParams) > 3 {
				if w, err := syslog.Dial(sysLogParams[1], sysLogParams[2], syslog.LOG_ALERT|syslog.LOG_CRIT|syslog.LOG_WARNING|syslog.LOG_INFO, "goconnect"); err != nil {
					log.SetOutput(w)
				} else {
					fmt.Printf("can not activate syslog with error %s\n", err.Error())
				}
			}
		}
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *CServer) handleSignals() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)

	<-sigc

	//Send termination command to all the active interfaces
	thisPt.nicManager.Flush()
	time.Sleep(1 * time.Second)

	log.Printf("successfully terminated\n")
}

//---------------------------------------------------------------------------------------

func (thisPt *CServer) init() {
	settings := flag.String("f", "", "static configuration")
	version := flag.Bool("version", false, "")

	flag.Parse()

	if *version {
		fmt.Printf("goconnect version %s \n", common.GOCONNECTVERSION)
		return
	}

	//create utils
	thisPt.utils = utils.Create()

	//load settings
	setInfo := sSettingsInitparams{}
	setInfo.FileName = *settings
	setInfo.Util = thisPt.utils
	if err := thisPt.settings.init(setInfo); err != nil {
		log.Fatalln(err)
	}

	//
	thisPt.initLog()

	//
	thisPt.initDB()

	//
	thisPt.initAuthenticators()

	//
	thisPt.initCommander()

	//
	thisPt.initNetworkSubsystems()

	//
	thisPt.initProtocols()

	//
	log.Printf("successfully initialized !\n")

	//Block the caller process
	thisPt.handleSignals()
}

//---------------------------------------------------------------------------------------

//Create ...
func Create() {
	server := CServer{}
	server.init()
}

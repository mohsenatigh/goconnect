package protocols

import (
	"goconnect/common"
	"net"
)

//---------------------------------------------------------------------------------------

//SESPInitParams ...
type SESPInitParams struct {
	Name           string
	IPList         []string
	Routes         []string
	Mtu            int
	BindAddress    string
	PeerAddress    string
	PeerPSK        string
	MyPSK          string
	Utils          common.IUtils
	PacketFactory  common.IProcessFactory
	ProtocolActor  common.IProtocolActor
	NetworkManager common.INICManager
}

//---------------------------------------------------------------------------------------

type cESP struct {
	cNICBase
	params       SESPInitParams
	serverSocket net.UDPConn
	clientSocket net.UDPConn
}

//---------------------------------------------------------------------------------------

func (thisPt *cESP) Init(param SESPInitParams) {
	thisPt.params = param
}

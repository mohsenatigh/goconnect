package common

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

//---------------------------------------------------------------------------------------

//public constants
const (
	GOCONNECTVERSION        = "1.0.0"  //system version
	LIMITSMAXUSERNAMELEN    = 64       //maximum username length
	LIMITSMAXPASSWORDLEN    = 64       //maximum passowrd length
	MAXAUTHFAILCOUNT        = 3        //Maximum loginfail count
	MAXAUTHTRACKTIME        = 60       //Maximum authentication failure tracking time
	MAXCONFIGFILESIZE       = 32000000 //Configuration file maximum size
	MAXCOMMANDRESPONSEITEMS = 1024     //Maximum objects count returned
)

//---------------------------------------------------------------------------------------

//TAccessFunction general function used for protected access to objects
type TAccessFunction func(object interface{})

//---------------------------------------------------------------------------------------

//IBuffer ...
type IBuffer interface {
	Write(data []byte) (int, error)
	ReadN(rlen uint32) []byte
	Read([]byte) (int, error) //for io.Reader
	ReadAll() []byte
	GetBuffer() []byte
	AddUsed(len uint32)
	ReadUntil(token []byte) []byte
	Seek(pos uint32)
	Reset()
	GetUsedSize() uint32
	GetTotalSize() uint32
	GetUnReadSize() uint32
	RemoveRead()
	String() string
}

//---------------------------------------------------------------------------------------

//STransferStat ...
type STransferStat struct {
	SendByte      uint64 `json:"send_byte"`
	ReceiveByte   uint64 `json:"receive_byte"`
	SendPacket    uint64 `json:"send_packet"`
	ReceivePacket uint64 `json:"receive_packet"`
}

func (thisPt STransferStat) GetValue(param string) uint64 {
	if param == "receive" {
		return thisPt.ReceiveByte
	} else if param == "send" {
		return thisPt.SendByte
	} else if param == "send_p" {
		return thisPt.SendPacket
	} else if param == "receive_p" {
		return thisPt.ReceivePacket
	} else if param == "total_p" {
		return thisPt.ReceivePacket + thisPt.SendPacket
	}
	return (thisPt.SendByte + thisPt.ReceiveByte)
}

//---------------------------------------------------------------------------------------

//SIPNet Sub class net.IPNet so that we can add JSON marshalling
type SIPNet net.IPNet

func (thisPt SIPNet) MarshalJSON() ([]byte, error) {
	_, bits := thisPt.Mask.Size()
	if thisPt.IP == nil {
		return json.Marshal("0.0.0.0/32")
	}
	return json.Marshal(fmt.Sprintf("%s/%d", thisPt.IP.String(), bits))
}

//---------------------------------------------------------------------------------------

//IDatabase ...
type IDatabase interface {
	LoadObject(objects interface{}, query string, args ...interface{}) error
	NormalizeString(input string) string
	RemoveObject(tableName string, object interface{}) error
	UpdateObject(tableName string, object interface{}) error
	SerializeObject(tableName string, object interface{}) error
	Register(tableName string, object interface{}) error
}

//---------------------------------------------------------------------------------------

//IIPPool ...
type IIPPool interface {
	AllocateIP() (bool, net.IP)
	FreeIP(net.IP)
}

//---------------------------------------------------------------------------------------

//THashCompareFunc ...
type THashCompareFunc func(inHashData interface{}, userdata interface{}) bool

//THashTimeOutFunc ...
type THashTimeOutFunc func(inHashData interface{}, userdata interface{}, delta int64) bool

//THashTimeOutFunc ...
type THashIterationFunc func(inHashData interface{}) bool

//IHashLinkList ...
type IHashLinkList interface {
	Add(key uint64, data interface{})
	Remove(key uint64, cmpFunc THashCompareFunc, userData interface{})
	Find(key uint64, cmpFunc THashCompareFunc, userData interface{}) interface{}
	CheckForTimeOut(cmpFunc THashTimeOutFunc, userData interface{}, t int64) int
	Clear()
	GetItemsCount() uint32
	Iterate(callBack THashIterationFunc) uint32
}

//---------------------------------------------------------------------------------------

//IHttpResponse ...
type IHTTPResponse interface {
	Header() http.Header
	Write(data []byte) (int, error)
	WriteJson(data interface{}) error
	WriteHeader(statusCode int)
	ToByte() []byte
	Copy(writer http.ResponseWriter)
	GetRespose() http.Response
}

//---------------------------------------------------------------------------------------

//TIPTrieCallBackFunc ...
type TIPTrieCallBackFunc func(interface{})

//IIPTrie ...
type IIPTrie interface {
	AddString(ipMask string, value interface{}) error
	Add(ip net.IP, mask uint32, value interface{})
	SearchString(ip string) interface{}
	Search(ip net.IP) interface{}
	SearchExact(ip net.IP, mask uint32) interface{}
	SearchExactString(ipMask string) interface{}
	Remove(ip net.IP, mask uint32) interface{}
	RemoveString(ipMask string) interface{}
	Iterate(callback TIPTrieCallBackFunc) uint32
}

//---------------------------------------------------------------------------------------

//ILoginFailTracker ...
type ILoginFailTracker interface {
	RegisterFail(id string) bool
	CanLogin(id string) bool
}

//---------------------------------------------------------------------------------------

// THeapSorterCallBackFunc
type THeapSorterCallBackFunc func(key string, item interface{}) uint64

//IHeapSorter
type IHeapSorter interface {
	AddItem(object interface{})
	GetItem() interface{}
	ToJson() string
}

//---------------------------------------------------------------------------------------

//IUtils ...
type IUtils interface {
	CreateNewIPTrie(ipVersion int) IIPTrie
	CreateLocalIPPool(start string, end string) IIPPool
	CreateHashLinkList(segmentCount uint32, inactveTimeOut uint64) IHashLinkList
	CreateBuffer(len uint32) IBuffer
	GetUniqID() uint64
	GetRandomString(uint32) string
	GetHexString(int) string
	FillRandomBuffer(buf []byte)
	DecryptData(key []byte, iv []byte, in string, data interface{}) error
	EncryptData(key []byte, iv []byte, data interface{}) string
	ParseJSONC(json string) string
	IsValidName(name string) bool
	ValidateStruct(input interface{}) error
	GenerateCert() (string, string, error)
	LoadCerts(certFile string, keyFile string) (tls.Certificate, error)
	GetHelp(input interface{}) string
	CreateHttpResponse() IHTTPResponse
	CreateLoginFailTracker(failCount uint32, maxTrackTime uint32) ILoginFailTracker
	LoadJsonFile(fileName string) (string, error)
	CreateHeapSorter(itemsCount uint32, callback THeapSorterCallBackFunc, param string) IHeapSorter
	CreateHttpResponseFromObject(object interface{}) (IHTTPResponse, error)
	CreateHttpResponseFromBuffer(buffer []byte) (IHTTPResponse, error)
	CreateHttpResponseFromString(buffer string) (IHTTPResponse, error)
	CastJsonObject(in interface{}, out interface{}) error
}

//---------------------------------------------------------------------------------------

//IGeoLocation ...
type IGeoLocation interface {
	//return result,country code, AS number
	GetIPInfo(ip net.IP) (bool, int, int)
	GetIPReputation(ip net.IP) (bool, int)
}

//---------------------------------------------------------------------------------------

//
const (
	INICTypeTUN    = 1
	INICTypeTunnel = 2
	INICTypePeer   = 3
	INICTypeClient = 4
	INICTypeMax    = 5
)

//INIC ...
type INIC interface {
	GetID() uint64
	GetName() string
	GetType() uint32
	GetStat() STransferStat
	GetPeerIP() net.IP
	GetVirtualIP() net.IP
	GetRoutes() []net.IPNet
	WriteData(data IProcessInfo)
	End()
}

//---------------------------------------------------------------------------------------

//INICManager ...
type INICManager interface {
	RegisterNIC(INIC)
	GetNICName(uint64) string
	RemoveNIC(uint64)
	WriteData(id uint64, data IProcessInfo)
	Flush()
}

//---------------------------------------------------------------------------------------

//Common L4 protocols
const (
	L4PROTOCOLICMP = 1
	L4PROTOCOLTCP  = 6
	L4PROTOCOLUDP  = 17
)

//---------------------------------------------------------------------------------------

//FlowDirection
const (
	FLOWDIRECTIONSEND   = 1
	FLOWDIRECTIONRECIVE = 2
)

//---------------------------------------------------------------------------------------

//IMetrics ...
type IMetrics interface {
	UpdateTotalSend(uint32)
	UpdateTotalReceive(uint32)
	UpdateTotalSendP(uint32)
	UpdateTotalReceiveP(uint32)
	UpdateAuthRequest(uint32)
	UpdateAuthSuccess(uint32)
	UpdateAuthFail(uint32)
	UpdateAccRequest(uint32)
	UpdateAccFail(uint32)
	UpdateAccDC(uint32)
	UpdateOnlineSessions(int)
	UpdateOnlineUser(userName string, add bool)
}

//---------------------------------------------------------------------------------------

//IProcessInfo ...
type IProcessInfo interface {
	GetBuffer() []byte
	GetUsedSize() uint32
	GetClientIP() net.IP
	SetClientIP(net.IP)
	GetSourceIP() net.IP
	GetDestinationIP() net.IP
	GetApplicationPayload() []byte
	GetIPVersion() uint8
	GetL4Protocol() uint8
	GetSourcePort() uint16
	GetDestinationPort() uint16
	GetClientVirtualIP() net.IP
	SetClientVirtualIP(net.IP)
	GetInNIC() uint64
	SetInNIC(uint64)
	GetOutNIC() uint64
	SetOutNIC(uint64)
	GetFlowKey() uint64
	ProcessAsNetPacket() bool
	String() string
}

//---------------------------------------------------------------------------------------

//IFlow ...
type IFlow interface {
	GetStat() STransferStat
	GetSource() net.IP
	GetDestinatin() net.IP
	GetInNIC() uint64
	GetOutNIC() uint64
	SetOutNIC(uint64)
	GetDirection(IProcessInfo) uint32
	GetID() uint64
	GetBlocked() bool
}

//---------------------------------------------------------------------------------------

//IFlowManager ...
type IFlowManager interface {
	GetFlow(IProcessInfo) IFlow
	GetFlowCount() uint32
}

//---------------------------------------------------------------------------------------

//IProcessFactory ...
type IProcessFactory interface {
	CreateProcessInfo([]byte) IProcessInfo
	FreeProcessInfo(process IProcessInfo)
	CreateProcessInfoByName(name string) IProcessInfo
	CreateRandomProcessInfoByName(name string) IProcessInfo
}

//---------------------------------------------------------------------------------------

//ROUTEMETRIC
const (
	ROUTEMETRICCONNECTED = 0
	ROUTEMETRICLOCAL     = 1
	ROUTEMETRICSTATIC    = 2
	ROUTEMETRICREMOTE    = 3
)

//IRouter ...
type IRouter interface {
	RegisterRoute(network net.IPNet, nicID uint64, nicName string, metric uint32)
	RemoveRoute(network net.IPNet, nicID uint64)
	GetDestinatin(ip net.IP) uint64
}

//---------------------------------------------------------------------------------------

//IProtocolActor ...
type IProtocolActor interface {
	OnNewPacket(IProcessInfo)
}

//---------------------------------------------------------------------------------------

//TAccountingSessionDC disconnect callback
type TAccountingSessionDC func(session IAccountingSession, userData interface{}) bool

//IAccountingSession ...
type IAccountingSession interface {
	GetSessionID() string
	GetUserName() string
	GetTransfer() STransferStat
	GetStepTransfer() STransferStat
	GetAuthenticationType() string
	GetLocation() (float64, float64)
	GetVIP() net.IP
	GetIP() net.IP
	GetStartTime() int64
	GetUpdateTime() int64
	UpdateSend(uint64)
	UpdateReceive(uint64)
	UpdateLocation(lat float64, long float64)
	RegisterDCCallBack(TAccountingSessionDC, interface{})
	Start()
	Stop()
	Update() bool
}

//---------------------------------------------------------------------------------------
//
const (
	IAuthenticatorAdminTypeFail     = 0
	IAuthenticatorAdminTypeFull     = 1
	IAuthenticatorAdminTypeReadOnly = 2
)

//SAuthenticationInfo ...
type SAuthenticationInfo struct {
	Lat      float64
	Long     float64
	User     string
	Password string
	IP       net.IP
}

//SAccountingInfo ...
type SAccountingInfo struct {
	User      string
	UserIP    net.IP
	VirtualIP net.IP
}

//IAuthenticator ...
type IAuthenticator interface {
	AuthenticateUser(info SAuthenticationInfo) error
	AuthenticateAdmin(info SAuthenticationInfo) (int, error)
	GetType() string
	CreateAccountingSession(info SAccountingInfo) IAccountingSession
}

//---------------------------------------------------------------------------------------

//IAuthenticationManger ..
type IAuthenticationManger interface {
	SetDummyInfo(userPass string, adminPass string)
	RegisterDummyAuthenticator(cfgFile string) error
	GetAuthenticator(typeName string) IAuthenticator
	GetAccountingSession(sessionID string, accessFunc TAccessFunction) error
	AuthenticateUser(info SAuthenticationInfo) (IAuthenticator, error)
	AuthenticateAdmin(info SAuthenticationInfo) (IAuthenticator, int, error)
	SetCommander(commander ICommander)
}

//---------------------------------------------------------------------------------------

//ICommanderActor ...
type ICommanderActor interface {
	OnCommand(api string, req *http.Request, params interface{}) (IHTTPResponse, error)
}

//---------------------------------------------------------------------------------------

//TCommanderSelectorActor ...
type TCommanderSelectorActor func(req *http.Request, params interface{}) (IHTTPResponse, error)

//ICommanderSelector ...
type ICommanderSelector interface {
	Register(api string, actor TCommanderSelectorActor, param interface{})
}

//---------------------------------------------------------------------------------------

//ICommander ...
type ICommander interface {
	CreateSelector() ICommanderSelector
	RegisterCommand(path string, param interface{}, actor ICommanderActor)
	HandleCommand(req *http.Request) (IHTTPResponse, error)
}

//---------------------------------------------------------------------------------------

//ICommanderActor ...
type IDynamicConfigActor interface {
	OnCommand(section string, params interface{}) error
}

//---------------------------------------------------------------------------------------

//IDynamicConfigManager ...
type IDynamicConfigManager interface {
	RegisterActor(segment string, param interface{}, actor IDynamicConfigActor)
	LoadConfig(configuration string) error
	LoadFile(fileName string) error
}

//---------------------------------------------------------------------------------------

//IPolicyMatchObject
type IPolicyMatchObjectManager interface {
	MatchObject(name string, process IProcessInfo, side uint32) bool
	GetObjectType(name string) (bool, string)
	GetObjectLocation(name string) (bool, uint32)
}

//---------------------------------------------------------------------------------------

//IPolicyMatchObject
type IPolicy interface {
	GetName() string
	GetOrder() uint32
	Match(process IProcessInfo) uint32
}

//---------------------------------------------------------------------------------------

//GRPC FUNCTIONS
//	PullNodes()
//	PullLeafs()
//	PushLeafs()
//	Subscribe() return a list of nodes

//INodes ...
type INodes interface {
	GetID() uint64
	GetNetwork() string
	GetIP() net.IP
	GetUpTime() uint32
	GetLastSeen() uint32
	GetAuthKey() string
}

//---------------------------------------------------------------------------------------

//ILeaf ...
type ILeaf interface {
	GetID() uint64
	GetName() string
	GetVIP() net.IP
	GetNodeID() uint64
}

//---------------------------------------------------------------------------------------

//INodesActor ...
type INodesActor interface {
	OnNewNode(INodes)
	OnNewLeaf(ILeaf)
	OnRemoveNode(INodes)
	OnRemoveLeaf(ILeaf)
}

//---------------------------------------------------------------------------------------

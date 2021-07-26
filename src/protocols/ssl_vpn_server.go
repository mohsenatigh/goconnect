package protocols

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"goconnect/common"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

const sslVpnServerMAXReadBuffer = 16384

//---------------------------------------------------------------------------------------
const (
	sslVPNAgentOpenConnect     = 0
	sslVPNAgentCiscoAnyConnect = 1
	sslVPNAgentOther           = 2
)

//---------------------------------------------------------------------------------------

const (
	sslVPNFormTypeLogin         = 0
	sslVPNFormTypeRegisteration = 1
)

//---------------------------------------------------------------------------------------

const (
	sslCookieNameContext = "webvpncontext"
	sslCookieNameKey     = "webvpn"
)

//---------------------------------------------------------------------------------------

const (
	sslVpnServerStatusNone        = 0
	sslVpnServerStatusAuthRequest = 1
	sslVpnServerStatusAuthorized  = 2
	sslVpnServerStatusEstablished = 3
	sslVpnServerStatusInvalid     = 4
	sslVpnServerStatusCommand     = 5
)

//---------------------------------------------------------------------------------------

type sSSLVpnAuthenticationParam struct {
	UserName string `xml:"username" validate:"min=3,max=64,alphanum,required"`
	Password string `xml:"password" validate:"min=4,max=64"`
	Phone    string `xml:"phone" validate:"omitempty,max=30,numeric"`
}

//---------------------------------------------------------------------------------------

type sSSLVpnHTTPProcessResult struct {
	UserName      string
	Group         string
	Status        int
	Response      http.Response
	VirtualIP     net.IP
	Authenticator string
	SessionID     uint64
}

//---------------------------------------------------------------------------------------

type sSSLVpnServerConnectionInfo struct {
	httpStablishResults sSSLVpnHTTPProcessResult
	ClinetIP            net.IP
	Nic                 *cSSLVpnNIC
	Connection          net.Conn
	ControlBuffer       common.IBuffer
	AccSession          common.IAccountingSession
	ControlLock         sync.Mutex
}

//---------------------------------------------------------------------------------------

const sslVPNCSTPHEADERLEN = 8

const (
	sslCSTPPacketTypeDATA       = 0x00
	sslCSTPPacketTypeDPDREQ     = 0x03
	sslCSTPPacketTypeDPDRESP    = 0x04
	sslCSTPPacketTypeDISCONNECT = 0x05
	sslCSTPPacketTypeKEEPALIVE  = 0x07
	sslCSTPPacketTypeCOMPRESED  = 0x08
	sslCSTPPacketTypeTERMINATE  = 0x09
)

type sSSLVpnServerCSTPHeader struct {
	F1          byte
	F2          byte
	F3          byte
	F4          byte
	Len         uint16
	Payloadtype uint8
	Res         uint8
}

//---------------------------------------------------------------------------------------
const sslVpnCookieMagic = 0x19810211

type sSSLVpnServerContextCookie struct {
	Type          int
	RandomCounter uint32
	Salt          string
	Magic         uint32
}

//---------------------------------------------------------------------------------------

type sSSLVpnServerKeyCookie struct {
	UserName      string
	Authenticator string
	ClientIP      string
	VirtaulIP     string
	SessionID     uint64
	sSSLVpnServerContextCookie
}

//---------------------------------------------------------------------------------------

type sSSLVpnSessionInfo struct {
	VirtualIP net.IP
	IsActive  bool
}

//---------------------------------------------------------------------------------------

type sSSLVpnActiveSessionsIDS struct {
	IDList common.IHashLinkList
}

//---------------------------------------------------------------------------------------

//SSSLVpnInitParams ...
type SSSLVpnInitParams struct {
	CertFile                string
	KeyFile                 string
	Address                 string
	DPDInterval             uint16
	ClientsNetMask          string
	SplitTunnels            []string
	DNSServers              []string
	TunnelDNS               bool
	KeepAlive               uint32
	IdelTimeout             uint32
	RekeyInterval           uint32
	Mtu                     uint32
	InactiveSessionsTimeOut uint32
	Debug                   bool
	InboundManagemnet       bool
	Utils                   common.IUtils
	Command                 common.ICommander
	AuthMan                 common.IAuthenticationManger
	IPPool                  common.IIPPool
	PacketFactory           common.IProcessFactory
	ProtocolActor           common.IProtocolActor
	NetworkManager          common.INICManager
}

//---------------------------------------------------------------------------------------

type cSSLVpnServer struct {
	params         SSSLVpnInitParams
	encKey         [32]byte
	encIV          [16]byte
	randomCounter  uint32
	sessionCounter uint64
	certHash       [20]byte
	activeSessions sSSLVpnActiveSessionsIDS
}

//---------------------------------------------------------------------------------------

type cSSLVpnNIC struct {
	cNICBase
	connection        net.Conn
	serverObject      *cSSLVpnServer
	buffer            common.IBuffer
	lock              sync.Mutex
	accountingSession common.IAccountingSession
	ended             bool
}

//---------------------------------------------------------------------------------------

//Write override cNICBase.write
func (thisPt *cSSLVpnNIC) WriteData(data common.IProcessInfo) {

	//it should be much faster to get a lock rather than allocating a memory
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	//make data packet
	if err := thisPt.serverObject.makeCSTPPacket(data.GetBuffer(), sslCSTPPacketTypeDATA, thisPt.buffer); err != nil {
		log.Printf("can not create CSTP data packet \n")
		return
	}

	//write data
	if _, err := thisPt.connection.Write(thisPt.buffer.ReadAll()); err != nil {
		log.Printf("write failed with error %v \n", err)
		return
	}
	thisPt.UpdateReceive(data)

	//update statistics
	thisPt.accountingSession.UpdateReceive(uint64(data.GetUsedSize()))
}

//---------------------------------------------------------------------------------------

//Write override cNICBase.end
func (thisPt *cSSLVpnNIC) End() {
	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	//send disconnect request to the client
	thisPt.serverObject.makeCSTPPacket(nil, sslCSTPPacketTypeTERMINATE, thisPt.buffer)
	thisPt.connection.Write(thisPt.buffer.ReadAll())

	//set end flag
	thisPt.ended = true
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateKeyCookie(key sSSLVpnServerKeyCookie) string {
	key.Magic = sslVpnCookieMagic
	key.RandomCounter = thisPt.randomCounter
	key.Salt = thisPt.params.Utils.GetRandomString(32)
	keyStr := thisPt.params.Utils.EncryptData(thisPt.encKey[0:], thisPt.encIV[0:], &key)
	return fmt.Sprintf("%s=%s", sslCookieNameKey, keyStr)
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateContextCookie(authType int) string {
	contextInfo := sSSLVpnServerContextCookie{}
	contextInfo.Magic = sslVpnCookieMagic
	contextInfo.RandomCounter = thisPt.randomCounter
	contextInfo.Salt = thisPt.params.Utils.GetRandomString(32)
	contextInfo.Type = authType
	contextStr := thisPt.params.Utils.EncryptData(thisPt.encKey[0:], thisPt.encIV[0:], &contextInfo)
	return fmt.Sprintf("%s=%s", sslCookieNameContext, contextStr)
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateHTTPResponseObject(value string) http.Response {

	resp := http.Response{
		Body:   ioutil.NopCloser(bytes.NewBufferString(value)),
		Header: make(map[string][]string),
	}

	resp.ContentLength = int64(len(value))
	resp.StatusCode = 200
	resp.ProtoMinor = 1
	resp.ProtoMajor = 1

	return resp
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) getAgentType(req *http.Request) int {

	agent := req.Header.Get("User-Agent")

	if strings.Contains(agent, "Open AnyConnect") || strings.Contains(agent, "OpenConnect-GUI") {
		return sslVPNAgentOpenConnect
	} else if strings.Contains(agent, "AnyConnect") {
		return sslVPNAgentCiscoAnyConnect
	}
	return sslVPNAgentOther
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateHTTPInitResponse(formType int) http.Response {

	responseTemplate :=
		`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
	<version who="sg">0.1(1)</version>
	<auth id="main">
		<message> %s </message>
		<form method="post" action="/%s">
			%s
		</form>
	</auth>
</config-auth>
`
	action := "auth"
	msg := "Please enter your username and password."
	if formType == sslVPNFormTypeRegisteration {
		action = "register"
		msg = "Please enter your information"
	}

	inputs := `<input type="text" name="username" label="Username:" />`
	if formType == sslVPNFormTypeLogin {
		inputs += `<input type="password" name="password" label="Password:" />`
	} else if formType == sslVPNFormTypeRegisteration {
		inputs += `<input type="text" name="phone" label="Phone:" />`
	}

	//make body
	respStr := fmt.Sprintf(responseTemplate, msg, action, inputs)

	//create response object
	resp := thisPt.generateHTTPResponseObject(respStr)
	contextCooki := thisPt.generateContextCookie(formType)
	resp.Header.Add("Set-Cookie", contextCooki)
	resp.Header.Add("Content-Type", "text/xml")
	resp.Header.Add("X-Transcend-Version", "1")
	return resp
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateHTTPAuthError(msg string) http.Response {
	resp := thisPt.generateHTTPResponseObject(msg)
	resp.StatusCode = 401
	return resp
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) isValidsessionID(id uint64) bool {

	//Keep session acive
	return (thisPt.activeSessions.IDList.Find(id, nil, nil) != nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) removeSessionID(id uint64) {

	//When this function is called the client can't use her token anymore
	releaseIP := func(inHashData interface{}, userdata interface{}) bool {
		session := inHashData.(*sSSLVpnSessionInfo)
		thisPt.params.IPPool.FreeIP(session.VirtualIP)
		return true
	}
	thisPt.activeSessions.IDList.Remove(id, releaseIP, nil)

}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) setSessionStatus(id uint64, status bool) {

	//
	setStatus := func(inHashData interface{}, userdata interface{}) bool {
		session := inHashData.(*sSSLVpnSessionInfo)
		session.IsActive = status
		return true
	}
	thisPt.activeSessions.IDList.Find(id, setStatus, nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateSessionID() (uint64, net.IP) {

	//allocate IP
	res, ip := thisPt.params.IPPool.AllocateIP()
	if !res {
		log.Printf("out of IP \n")
		return 0, nil
	}

	//generate a uniq session IF
	id := atomic.AddUint64(&thisPt.sessionCounter, 1)

	sessionInfo := new(sSSLVpnSessionInfo)
	sessionInfo.IsActive = true
	sessionInfo.VirtualIP = ip
	thisPt.activeSessions.IDList.Add(id, sessionInfo)
	return id, sessionInfo.VirtualIP
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) removeInactiveSessions(t int64) {

	//Check current sessions and try to remove inactive ones
	checkFunction := func(inHashData interface{}, userdata interface{}, delta int64) bool {
		session := inHashData.(*sSSLVpnSessionInfo)
		if !session.IsActive {
			session := inHashData.(*sSSLVpnSessionInfo)
			thisPt.params.IPPool.FreeIP(session.VirtualIP)
			return true
		}
		return false
	}

	thisPt.activeSessions.IDList.CheckForTimeOut(checkFunction, nil, t)
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateHTTPGetResponse(req *http.Request, conetionInfo *sSSLVpnServerConnectionInfo) http.Response {
	resp := http.Response{}

	if req.URL.Path == "/1/binaries/update.txt" {
		resp = thisPt.generateHTTPResponseObject("0,00,000\n")
	} else if req.URL.Path == "/1/binaries/vpndownloader.exe" {
		resp = thisPt.generateHTTPResponseObject("<html><body><h1>404 Not Found</h1></body></html>\n")
		resp.StatusCode = 404
	} else {
		resp = thisPt.generateHTTPResponseObject("<html></html>\n")
	}
	resp.Header.Add("Content-Type", "text/html")
	return resp
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateHTTPStablishResponse(req *http.Request, virtualIP string) http.Response {

	resp := thisPt.generateHTTPResponseObject("")
	resp.Status = "200 CONNECTED"

	//Golang HTTP request header uses canonical mode by default.
	//This type of header is not accepted by current clients

	header := make(http.Header)

	Add := func(key, val string) {
		header[key] = append(header[key], val)
	}

	//add headers
	Add("X-CSTP-Version", "1")
	Add("X-CSTP-Server-Name", fmt.Sprintf("goconnect %s", common.GOCONNECTVERSION))
	Add("X-CSTP-Hostname", "goconnect")
	Add("X-CSTP-DPD", fmt.Sprintf("%d", thisPt.params.DPDInterval))
	Add("X-CSTP-Address", virtualIP)
	Add("X-CSTP-Netmask", thisPt.params.ClientsNetMask)
	for _, ip := range thisPt.params.SplitTunnels {
		Add("X-CSTP-Split-Include", ip)
	}
	Add("X-CSTP-Tunnel-All-DNS", fmt.Sprintf("%v", thisPt.params.TunnelDNS))
	Add("X-CSTP-Keepalive", fmt.Sprintf("%d", thisPt.params.KeepAlive))
	if thisPt.params.IdelTimeout != 0 {
		Add("X-CSTP-Idle-Timeout", fmt.Sprintf("%d", thisPt.params.IdelTimeout))
	}
	Add("X-CSTP-Rekey-Time", fmt.Sprintf("%d", thisPt.params.RekeyInterval))
	Add("X-CSTP-Rekey-Method", "ssl")
	Add("X-CSTP-Session-Timeout", "none")
	Add("X-CSTP-Disconnected-Timeout", "none")
	Add("X-CSTP-Keep", "true")
	Add("X-CSTP-TCP-Keepalive", "true")
	Add("X-CSTP-License", "accept")
	Add("X-CSTP-Base-MTU", "1500")
	Add("X-CSTP-MTU", fmt.Sprintf("%d", thisPt.params.Mtu))

	//add DNS
	for _, dns := range thisPt.params.DNSServers {
		Add("X-CSTP-DNS:", dns)
	}

	resp.Header = header
	return resp
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) generateHTTPAuthResponse(req *http.Request, conetionInfo *sSSLVpnServerConnectionInfo) http.Response {

	//get current context
	contextCooki, err := req.Cookie(sslCookieNameContext)
	if err != nil || !thisPt.isValidContext(contextCooki) {
		return thisPt.generateHTTPAuthError("invalid request")
	}

	contextInfo, res := thisPt.decodeContextCookie(contextCooki.Value)
	if !res {
		return thisPt.generateHTTPAuthError("invalid request")
	}

	//get forms input
	formInfo, res := thisPt.parseAuthForm(req)
	if !res {
		return thisPt.generateHTTPAuthError("invalid request")
	}

	//check for auth type
	if contextInfo.Type == sslVPNFormTypeRegisteration {
		//TODO Register User
		return thisPt.generateHTTPInitResponse(sslVPNFormTypeLogin)
	}

	authParm := common.SAuthenticationInfo{}
	authParm.IP = conetionInfo.ClinetIP
	authParm.User = formInfo.UserName
	authParm.Password = formInfo.Password
	auth, err := thisPt.params.AuthMan.AuthenticateUser(authParm)
	if err != nil {
		return thisPt.generateHTTPAuthError(err.Error())
	}

	//allocate IP
	sessionID, vip := thisPt.generateSessionID()
	if sessionID == 0 {
		return thisPt.generateHTTPAuthError("out of IP")
	}

	//create key
	keyInfo := sSSLVpnServerKeyCookie{}
	keyInfo.UserName = formInfo.UserName
	keyInfo.Authenticator = auth.GetType()
	keyInfo.ClientIP = conetionInfo.ClinetIP.String()
	keyInfo.VirtaulIP = vip.String()
	keyInfo.SessionID = sessionID

	keyCookieStr := thisPt.generateKeyCookie(keyInfo)
	contextCookiStr := thisPt.generateContextCookie(sslVPNFormTypeLogin)

	//create finall request
	responseTemplate :=
		`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
<version who="sg">0.1(1)</version>
<auth id="success">
<title>SSL VPN Service</title></auth></config-auth>`

	responseObj := thisPt.generateHTTPResponseObject(responseTemplate)
	responseObj.Header.Add("Set-Cookie", keyCookieStr)
	responseObj.Header.Add("Set-Cookie", contextCookiStr)
	responseObj.Header.Add("Set-Cookie", "webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure")

	certHex := strings.ToUpper(hex.EncodeToString(thisPt.certHash[0:]))
	responseObj.Header.Add("Set-Cookie", fmt.Sprintf("webvpnc=bu:/&p:t&iu:1/&sh:%s; path=/; Secure", certHex))
	responseObj.Header.Add("Content-Type", "text/xml")
	responseObj.Header.Add("X-Transcend-Version", "1")

	return responseObj
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) parseAuthForm(req *http.Request) (sSSLVpnAuthenticationParam, bool) {

	type sSSLVPNAuthXML struct {
		Config   string                     `xml:"config-auth"`
		Version  string                     `xml:"version"`
		DeviceID string                     `xml:"device-id"`
		Auth     sSSLVpnAuthenticationParam `xml:"auth"`
	}

	xmlParam := sSSLVPNAuthXML{}
	param := sSSLVpnAuthenticationParam{}

	//check url
	if req.RequestURI != "/auth" {
		return param, false
	}

	//for open connect the content-type will be set to "application/x-www-form-urlencoded"
	//but for the Cisco client it is empty
	agentType := thisPt.getAgentType(req)
	if agentType == sslVPNAgentOpenConnect {
		if err := xml.NewDecoder(req.Body).Decode(&xmlParam); err != nil {
			log.Printf("invalid authentication parameters {%s} \n", err.Error())
			return param, false
		}
		param = xmlParam.Auth
	} else if agentType == sslVPNAgentCiscoAnyConnect {

		//Itis against the RFC. but Golang HTTP parser  is not able to parse HTTP request form data
		//if the content type is not "application/x-www-form-urlencoded"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			log.Printf("invalid authentication parameters {%s} \n", err.Error())
			return param, false
		}
		param.UserName = req.FormValue("username")
		param.Password = req.PostFormValue("password")
		param.Phone = req.PostFormValue("phone")
	} else {
		//some thing new !
		log.Printf("invalid authentication parameters \n")
		return param, false
	}

	//validate
	if err := thisPt.params.Utils.ValidateStruct(param); err != nil {
		log.Printf("invalid authentication parameters {%s} \n", err.Error())
		return param, false
	}

	return param, true
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) decodeContextCookie(data string) (sSSLVpnServerContextCookie, bool) {
	contextInfo := sSSLVpnServerContextCookie{}

	//decrypt cookie
	if thisPt.params.Utils.DecryptData(thisPt.encKey[0:], thisPt.encIV[0:], data, &contextInfo) != nil {
		return contextInfo, false
	}

	//validate cookie
	if contextInfo.Magic != sslVpnCookieMagic || contextInfo.RandomCounter != thisPt.randomCounter {
		return contextInfo, false
	}

	return contextInfo, true
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) decodeKeyCookie(data string) (sSSLVpnServerKeyCookie, bool) {
	keyInfo := sSSLVpnServerKeyCookie{}

	//decrypt cookie
	if thisPt.params.Utils.DecryptData(thisPt.encKey[0:], thisPt.encIV[0:], data, &keyInfo) != nil {
		return keyInfo, false
	}

	//validate cookie
	if keyInfo.Magic != sslVpnCookieMagic || keyInfo.RandomCounter != thisPt.randomCounter {
		return keyInfo, false
	}
	return keyInfo, true
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) isValidContext(cookie *http.Cookie) bool {
	if cookie == nil {
		return false
	}
	if _, res := thisPt.decodeContextCookie(cookie.Value); res {
		return true
	}
	return false
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) isValidKey(cookie *http.Cookie, ip net.IP) bool {

	//removing inactive or zombie sessions
	defer func() {
		thisPt.removeInactiveSessions(0)
	}()

	if cookie == nil {
		return false
	}

	if value, res := thisPt.decodeKeyCookie(cookie.Value); res {
		if value.ClientIP == ip.String() && thisPt.isValidsessionID(value.SessionID) {
			//keep the session active, otherwise, it will be removed from the list
			thisPt.setSessionStatus(value.SessionID, true)
			return true
		}
	}
	return false
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) getStatus(req *http.Request, conInfo *sSSLVpnServerConnectionInfo) int {
	context, noContext := req.Cookie(sslCookieNameContext)
	key, noKey := req.Cookie(sslCookieNameKey)

	//check for key
	if noKey == nil {
		if thisPt.isValidKey(key, conInfo.ClinetIP) {
			return sslVpnServerStatusAuthorized
		} else {
			return sslVpnServerStatusInvalid
		}
	}

	//check for context
	if noContext == nil {
		if thisPt.isValidContext(context) {
			return sslVpnServerStatusAuthRequest
		} else {
			return sslVpnServerStatusInvalid
		}
	}

	return sslVpnServerStatusNone
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) processHTTPCommands(req *http.Request) (http.Response, int) {

	//command
	if thisPt.params.Command == nil || !thisPt.params.InboundManagemnet {
		return http.Response{}, sslVpnServerStatusInvalid
	}

	//handle command
	out, err := thisPt.params.Command.HandleCommand(req)
	if err != nil {
		log.Printf("handling command failed with error %s \n", err.Error())
		return http.Response{}, sslVpnServerStatusInvalid
	}

	return out.GetRespose(), sslVpnServerStatusCommand
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) processHTTPRequest(req *http.Request, conInfo *sSSLVpnServerConnectionInfo) sSSLVpnHTTPProcessResult {
	result := sSSLVpnHTTPProcessResult{}
	result.Status = sslVpnServerStatusNone

	//set request object address info
	req.RemoteAddr = conInfo.Connection.RemoteAddr().String()

	//check for command
	userAgent := thisPt.getAgentType(req)

	if userAgent == sslVPNAgentOther {
		result.Response, result.Status = thisPt.processHTTPCommands(req)
		return result
	}

	//get connection status
	status := thisPt.getStatus(req, conInfo)
	if status == sslVpnServerStatusInvalid {
		result.Status = sslVpnServerStatusInvalid
		return result
	}

	//new connection
	if status == sslVpnServerStatusNone {
		result.Response = thisPt.generateHTTPInitResponse(sslVPNFormTypeLogin)
		return result
	}

	//process authentication information
	if status == sslVpnServerStatusAuthRequest {
		result.Status = sslVpnServerStatusAuthRequest
		result.Response = thisPt.generateHTTPAuthResponse(req, conInfo)
		return result
	}

	//process authorized connections
	if status == sslVpnServerStatusAuthorized {
		//checking for info request
		if req.Method == http.MethodGet {
			result.Response = thisPt.generateHTTPGetResponse(req, conInfo)
			return result
		} else if req.Method == http.MethodConnect {
			//The key must be valid here. Otherwise, we have a big logical bug
			key, _ := req.Cookie(sslCookieNameKey)
			keyVal, _ := thisPt.decodeKeyCookie(key.Value)

			//fill result
			result.Status = sslVpnServerStatusEstablished
			result.VirtualIP = net.ParseIP(keyVal.VirtaulIP).To4()
			result.UserName = keyVal.UserName
			result.Authenticator = keyVal.Authenticator
			result.Response = thisPt.generateHTTPStablishResponse(req, keyVal.VirtaulIP)
		} else {
			result.Status = sslVpnServerStatusAuthorized
		}
	}

	return result
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) readHTTP(buffer common.IBuffer) *http.Request {

	var req *http.Request

	//read http header
	data := buffer.ReadAll()

	//Adjusting read buffer
	defer func() {
		//here we need a clean way rather than the fast one
		if req == nil {
			buffer.Seek(0)
		} else {
			buffer.RemoveRead()
		}
	}()

	//parse header
	tmpreq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return nil
	}

	//estimating buffer usage
	header := buffer.ReadUntil([]byte("\r\n\r\n"))
	if header == nil {
		return nil
	}

	cntLen := uint32(tmpreq.ContentLength)
	//check for contnet size
	if cntLen > 0 {
		if body := buffer.ReadN(cntLen); uint32(len(body)) != cntLen {
			return nil
		}
	}
	req = tmpreq
	return req
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) makeCSTPPacket(data []byte, pType uint8, buffer common.IBuffer) error {

	buffer.Reset()

	header := sSSLVpnServerCSTPHeader{}

	header.F1 = 'S'
	header.F2 = 'T'
	header.F3 = 'F'
	header.F4 = 1
	header.Len = uint16(len(data))
	header.Res = 0
	header.Payloadtype = pType

	//write header
	if err := binary.Write(buffer, binary.BigEndian, &header); err != nil {
		return err
	}

	//write body
	if data != nil {
		if _, err := buffer.Write(data); err != nil {
			return err
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) processControlPackets(pType uint8, data []byte, connectionInfo *sSSLVpnServerConnectionInfo) (bool, error) {
	connectionInfo.ControlLock.Lock()
	defer connectionInfo.ControlLock.Unlock()

	sendReplay := func(outType uint8) {
		thisPt.makeCSTPPacket(nil, outType, connectionInfo.ControlBuffer)
		connectionInfo.Connection.Write(connectionInfo.ControlBuffer.ReadAll())
	}

	//check control packets
	if pType == sslCSTPPacketTypeDPDREQ {
		sendReplay(sslCSTPPacketTypeDPDRESP)
		return false, nil
	} else if pType == sslCSTPPacketTypeKEEPALIVE {
		sendReplay(sslCSTPPacketTypeKEEPALIVE)
		return false, nil
	} else if pType == sslCSTPPacketTypeDISCONNECT || pType == sslCSTPPacketTypeTERMINATE {
		return true, nil
	}
	return false, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cSSLVpnServer) readPacket(buffer common.IBuffer, connectionInfo *sSSLVpnServerConnectionInfo) (bool, error) {

	//
	defer func() {
		buffer.Seek(0)
	}()

	header := sSSLVpnServerCSTPHeader{}

	for {

		//check buffer size
		if buffer.GetUnReadSize() < sslVPNCSTPHEADERLEN {
			return false, nil
		}

		//read header
		if err := binary.Read(buffer, binary.BigEndian, &header); err != nil {
			return false, nil
		}

		//validate header
		if header.F1 != 'S' && header.F2 != 'T' && header.F3 != 'F' && header.F4 != 1 {
			return true, errors.New("invalid packet received")
		}

		//validate len
		if header.Len > (uint16(thisPt.params.Mtu) + 16) {
			return true, errors.New("invalid packet received")
		}

		//read body
		body := buffer.ReadN(uint32(header.Len))
		if len(body) != int(header.Len) {
			return false, nil
		}

		//check for control packets
		if header.Payloadtype != sslCSTPPacketTypeDATA {
			if dc, err := thisPt.processControlPackets(header.Payloadtype, body, connectionInfo); dc || err != nil {
				return true, err
			}
		} else {
			//create packet object
			packet := thisPt.params.PacketFactory.CreateProcessInfo(body)
			packet.SetClientVirtualIP(connectionInfo.httpStablishResults.VirtualIP)
			packet.SetClientIP(connectionInfo.ClinetIP)
			packet.SetInNIC(connectionInfo.Nic.GetID())
			if !packet.ProcessAsNetPacket() {
				return false, errors.New("invalid packet received")
			}

			//update nic status
			connectionInfo.Nic.UpdateSend(packet)
			connectionInfo.AccSession.UpdateSend(uint64(packet.GetUsedSize()))
			thisPt.params.ProtocolActor.OnNewPacket(packet)
		}

		//remove used bytes
		buffer.RemoveRead()
	}
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) registerInterface(connectionInfo *sSSLVpnServerConnectionInfo) *cSSLVpnNIC {
	nic := new(cSSLVpnNIC)
	nic.buffer = thisPt.params.Utils.CreateBuffer(sslVpnServerMAXReadBuffer)
	nic.connection = connectionInfo.Connection
	nic.Id = thisPt.params.Utils.GetUniqID()
	nic.Ip = connectionInfo.ClinetIP
	nic.VirtualIP = connectionInfo.httpStablishResults.VirtualIP
	nic.Name = fmt.Sprintf("ssl-vpn-%s", connectionInfo.httpStablishResults.UserName)
	nic.NicType = common.INICTypeClient
	nic.serverObject = thisPt
	nic.accountingSession = connectionInfo.AccSession
	nic.accountingSession.RegisterDCCallBack(func(session common.IAccountingSession, data interface{}) bool {
		//calling the end function in case of the accounting session termination
		nic := data.(*cSSLVpnNIC)
		nic.End()
		return true
	}, nic)

	netObj := net.IPNet{}
	netObj.IP = connectionInfo.httpStablishResults.VirtualIP
	if len(netObj.IP) == 4 {
		netObj.Mask = net.CIDRMask(32, 32)
	} else {
		netObj.Mask = net.CIDRMask(128, 128)
	}
	nic.Routes = append(nic.Routes, netObj)

	thisPt.params.NetworkManager.RegisterNIC(nic)

	return nic
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) unregisterInterface(nic *cSSLVpnNIC) {
	thisPt.params.NetworkManager.RemoveNIC(nic.GetID())
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) createAccSession(connectionInfo *sSSLVpnServerConnectionInfo) common.IAccountingSession {
	info := common.SAccountingInfo{}
	info.User = connectionInfo.httpStablishResults.UserName
	info.UserIP = connectionInfo.ClinetIP
	info.VirtualIP = connectionInfo.httpStablishResults.VirtualIP
	authenticator := thisPt.params.AuthMan.GetAuthenticator(connectionInfo.httpStablishResults.Authenticator)
	return authenticator.CreateAccountingSession(info)
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) stopAccSession(acc common.IAccountingSession) {
	acc.Stop()
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) handle(con net.Conn) {
	status := sslVpnServerStatusNone

	//create buffer
	buffer := thisPt.params.Utils.CreateBuffer(sslVpnServerMAXReadBuffer)

	//fill connection information object
	connectionInfo := sSSLVpnServerConnectionInfo{}
	ip := con.RemoteAddr().(*net.TCPAddr).IP
	connectionInfo.ClinetIP = ip.To4()
	if connectionInfo.ClinetIP == nil {
		connectionInfo.ClinetIP = ip
	}
	connectionInfo.Connection = con

	//this buffer is used for control packets
	connectionInfo.ControlBuffer = thisPt.params.Utils.CreateBuffer(sslVpnServerMAXReadBuffer)

	//exit function
	defer func() {
		con.Close()

		//remove interface
		if connectionInfo.Nic != nil {
			//In case of a normal shutdown, remove the session; otherwise, disable it
			if connectionInfo.Nic.ended {
				thisPt.removeSessionID(connectionInfo.httpStablishResults.SessionID)
			} else {
				thisPt.setSessionStatus(connectionInfo.httpStablishResults.SessionID, false)
			}
			thisPt.unregisterInterface(connectionInfo.Nic)
		}

		//remove acc session
		if connectionInfo.AccSession != nil {
			thisPt.stopAccSession(connectionInfo.AccSession)
		}
	}()

	//
	convertHTTPResponseToBuffer := func(respObject *http.Response) []byte {
		buff := bytes.NewBuffer(nil)
		respObject.Write(buff)
		return buff.Bytes()
	}

	//enter loop
	for {
		writeBuffer := buffer.GetBuffer()

		//check for buffer overflow
		if len(writeBuffer) == 0 {
			log.Printf("buffer overflow detected \n")
			return
		}

		//read from the socket
		n, err := con.Read(writeBuffer)

		//something is not good
		if err != nil {
			log.Printf("can not read from socket with error %s \n", err)
			return
		}
		buffer.AddUsed(uint32(n))

		//connection is in data mode
		if status == sslVpnServerStatusEstablished {
			dc, err := thisPt.readPacket(buffer, &connectionInfo)
			if err != nil {
				log.Printf("can not read data with error %s \n", err)
				return
			}

			if dc {
				return
			}
			continue
		}

		//read http request
		if thisPt.params.Debug {
			log.Printf("\n\n%v \n\n", buffer)
		}

		httpRequest := thisPt.readHTTP(buffer)
		if httpRequest == nil {
			continue
		}

		//process request
		httpResp := thisPt.processHTTPRequest(httpRequest, &connectionInfo)
		if httpResp.Status == sslVpnServerStatusInvalid {
			return
		}

		//write response
		outBuffer := convertHTTPResponseToBuffer(&httpResp.Response)
		if _, err := con.Write(outBuffer); err != nil {
			return
		}

		//update status
		status = httpResp.Status
		if thisPt.params.Debug {
			log.Printf("\n\n%v \n\n", string(outBuffer))
		}

		//check for status, if everything is fine, register virtual interface, and switch to data mode
		if status == sslVpnServerStatusEstablished {
			connectionInfo.httpStablishResults = httpResp

			//create accounting session
			connectionInfo.AccSession = thisPt.createAccSession(&connectionInfo)
			if connectionInfo.AccSession == nil {
				return
			}

			//create NIC
			connectionInfo.Nic = thisPt.registerInterface(&connectionInfo)
			if connectionInfo.Nic == nil {
				return
			}
		}
	}
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) loadCerts() tls.Certificate {
	cert, err := thisPt.params.Utils.LoadCerts(thisPt.params.CertFile, thisPt.params.KeyFile)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	return cert
}

//---------------------------------------------------------------------------------------

func (thisPt *cSSLVpnServer) Init(params SSSLVpnInitParams) error {

	//
	thisPt.params = params

	//load keys
	cert := thisPt.loadCerts()

	//calculate certificate finger print
	certData, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatalf("can not parse certificate with error %s\n", err.Error())
	}
	thisPt.certHash = sha1.Sum(certData.Raw)

	//
	const hashSegmentsCount = 32000
	thisPt.activeSessions.IDList = thisPt.params.Utils.CreateHashLinkList(hashSegmentsCount, uint64(params.InactiveSessionsTimeOut))

	//generate some random key
	thisPt.params.Utils.FillRandomBuffer(thisPt.encKey[0:])
	thisPt.params.Utils.FillRandomBuffer(thisPt.encIV[0:])
	thisPt.randomCounter = mrand.Uint32()

	//
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", params.Address, tlsCfg)
	if err != nil {
		log.Fatal(err)
	}

	//listen for incomming connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go thisPt.handle(conn)
		}
	}()

	return nil
}

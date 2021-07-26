package auth

import (
	"goconnect/common"
	"net"
	"time"
)

type cAccountingSessionBase struct {
	Transfer          common.STransferStat `json:"transfer"`
	User              string               `json:"user"`
	LocationLat       float64              `json:"location_lat"`
	LocationLong      float64              `json:"location_long"`
	StepTransfer      common.STransferStat `json:"step_transfer"`
	SessionID         string               `json:"session_id"`
	AuthenticatorType string               `json:"auth_type"`
	Ip                net.IP               `json:"client_ip"`
	Vip               net.IP               `json:"virtual_ip"`
	StartTime         int64                `json:"start_time"`
	UpdateTime        int64                `json:"update_time"`
	dcCallback        common.TAccountingSessionDC
	dcData            interface{}
	authManager       *cAuthenticationManager
}

//---------------------------------------------------------------------------------------

//GetSessionID for IAccountingSession
func (thisPt *cAccountingSessionBase) GetSessionID() string {
	return thisPt.SessionID
}

//---------------------------------------------------------------------------------------

//GetUserName for IAccountingSession
func (thisPt *cAccountingSessionBase) GetUserName() string {
	return thisPt.User
}

//---------------------------------------------------------------------------------------

//GetTransfer for IAccountingSession
func (thisPt *cAccountingSessionBase) GetTransfer() common.STransferStat {
	return thisPt.Transfer
}

//---------------------------------------------------------------------------------------

//GetStepSend for IAccountingSession
func (thisPt *cAccountingSessionBase) GetStepTransfer() common.STransferStat {
	return thisPt.StepTransfer
}

//---------------------------------------------------------------------------------------

//GetLocation for IAccountingSession
func (thisPt *cAccountingSessionBase) GetLocation() (float64, float64) {
	return thisPt.LocationLat, thisPt.LocationLong
}

//---------------------------------------------------------------------------------------

//GetAuthenticationType for IAccountingSession
func (thisPt *cAccountingSessionBase) GetAuthenticationType() string {
	return thisPt.AuthenticatorType
}

//---------------------------------------------------------------------------------------

//GetVIP for IAccountingSession
func (thisPt *cAccountingSessionBase) GetVIP() net.IP {
	return thisPt.Vip
}

//---------------------------------------------------------------------------------------

//GetIP for IAccountingSession
func (thisPt *cAccountingSessionBase) GetIP() net.IP {
	return thisPt.Ip
}

//---------------------------------------------------------------------------------------

//GetStartTime for IAccountingSession
func (thisPt *cAccountingSessionBase) GetStartTime() int64 {
	return thisPt.StartTime
}

//---------------------------------------------------------------------------------------

//GetUpdateTime for IAccountingSession
func (thisPt *cAccountingSessionBase) GetUpdateTime() int64 {
	return thisPt.UpdateTime
}

//---------------------------------------------------------------------------------------

//UpdateSend for IAccountingSession
func (thisPt *cAccountingSessionBase) UpdateSend(val uint64) {
	thisPt.Transfer.SendByte += val
	thisPt.Transfer.SendPacket++
	thisPt.StepTransfer.SendByte += val
	thisPt.StepTransfer.SendPacket++
}

//---------------------------------------------------------------------------------------

//UpdateReceive for IAccountingSession
func (thisPt *cAccountingSessionBase) UpdateReceive(val uint64) {
	thisPt.Transfer.ReceiveByte += val
	thisPt.Transfer.ReceivePacket++
	thisPt.StepTransfer.ReceiveByte += val
	thisPt.StepTransfer.ReceivePacket++
}

//---------------------------------------------------------------------------------------

//Remove for IAccountingSession
func (thisPt *cAccountingSessionBase) UpdateLocation(lat float64, long float64) {
	thisPt.LocationLat = lat
	thisPt.LocationLong = long
}

//---------------------------------------------------------------------------------------

//Remove for IAccountingSession
func (thisPt *cAccountingSessionBase) RegisterDCCallBack(callback common.TAccountingSessionDC, data interface{}) {
	thisPt.dcCallback = callback
	thisPt.dcData = data
}

//---------------------------------------------------------------------------------------

//Remove for IAccountingSession
func (thisPt *cAccountingSessionBase) Start() {
	thisPt.StartTime = time.Now().Unix()
}

//---------------------------------------------------------------------------------------

//Remove for IAccountingSession
func (thisPt *cAccountingSessionBase) Stop() {
	if thisPt.dcCallback != nil {
		thisPt.dcCallback(thisPt, thisPt.dcData)
	}
	thisPt.authManager.RemoveAccSession(thisPt)
}

//---------------------------------------------------------------------------------------

//Remove for IAccountingSession
func (thisPt *cAccountingSessionBase) Update() bool {
	thisPt.StepTransfer.SendByte = 0
	thisPt.StepTransfer.ReceiveByte = 0
	thisPt.StepTransfer.SendPacket = 0
	thisPt.StepTransfer.ReceivePacket = 0
	thisPt.UpdateTime = time.Now().Unix()
	return true
}

//---------------------------------------------------------------------------------------
func (thisPt *cAccountingSessionBase) Init(authManager *cAuthenticationManager, info common.SAccountingInfo, auth common.IAuthenticator, util common.IUtils) bool {
	const sessionIDLen = 32
	thisPt.Ip = info.UserIP
	thisPt.Vip = info.VirtualIP
	thisPt.User = info.User
	thisPt.AuthenticatorType = auth.GetType()
	thisPt.authManager = authManager

	//generate session id
	thisPt.SessionID = util.GetRandomString(sessionIDLen)

	authManager.RegisterAccSession(thisPt)

	return true
}

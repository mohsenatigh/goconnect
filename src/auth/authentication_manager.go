package auth

import (
	"errors"
	"goconnect/common"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

//---------------------------------------------------------------------------------------

type SAuthenticationManagerParams struct {
	Utils     common.IUtils
	Commander common.ICommander
}

//---------------------------------------------------------------------------------------

type sAuthenticationManagerListParams struct {
	User           string `help:"User Name" schema:"user" validate:"omitempty,min=2,max=64,alphanum"`
	ClientIP       string `help:"Clinet IP" schema:"ip" validate:"omitempty,cidr"`
	VirtualIP      string `help:"Virtual IP" schema:"v_ip" validate:"omitempty,cidr"`
	ID             string `help:"Session ID" schema:"id" validate:"omitempty,alphanum"`
	Sort           string `help:"Sort field, one of [total|send|receive|total_p|send_p|receive_p]. total by default" schema:"sort" validate:"omitempty,min=2,max=64,alphanum"`
	clientIPCache  *net.IPNet
	virtualIPCache *net.IPNet
}

//---------------------------------------------------------------------------------------

type sAuthenticationManagerListUsersParams struct {
	User string `help:"User Name" schema:"user" validate:"omitempty,min=2,max=64,alphanum"`
}

//---------------------------------------------------------------------------------------

type sAuthenticationManagerStat struct {
	LoginReqCount       uint64 `json:"login_count"`
	LoginFailCount      uint64 `json:"login_fail_count"`
	AdminLoginCount     uint64 `json:"admin_login_count"`
	AdminLoginFailCount uint64 `json:"admin_login_fail_count"`
	SessionsCount       uint64 `json:"acc_sessions_count"`
	UsersCount          uint64 `json:"acc_users_count"`
}

//---------------------------------------------------------------------------------------

type cAuthenticationManager struct {
	sessions       map[string]common.IAccountingSession
	users          map[string]uint32
	sessionsLock   sync.RWMutex
	authenticators []common.IAuthenticator
	authLocks      sync.RWMutex
	params         SAuthenticationManagerParams
	stat           sAuthenticationManagerStat
}

//---------------------------------------------------------------------------------------

func (thisPt *cAuthenticationManager) prepareSearchParam(params interface{}) *sAuthenticationManagerListParams {
	searchParam := params.(*sAuthenticationManagerListParams)
	_, searchParam.clientIPCache, _ = net.ParseCIDR(searchParam.ClientIP)
	_, searchParam.virtualIPCache, _ = net.ParseCIDR(searchParam.VirtualIP)
	return searchParam
}

//---------------------------------------------------------------------------------------

func (thisPt *cAuthenticationManager) registerAuthenticator(auth common.IAuthenticator) error {

	if thisPt.GetAuthenticator(auth.GetType()) != nil {
		return errors.New("duplicate authenticator registration")
	}

	thisPt.authLocks.Lock()
	defer thisPt.authLocks.Unlock()

	thisPt.authenticators = append(thisPt.authenticators, auth)
	return nil
}

//---------------------------------------------------------------------------------------

func (thisPt *cAuthenticationManager) matchSession(accSession common.IAccountingSession, param *sAuthenticationManagerListParams) bool {

	if param.clientIPCache != nil && !param.clientIPCache.Contains(accSession.GetIP()) {
		return false
	}

	if param.virtualIPCache != nil && !param.virtualIPCache.Contains(accSession.GetVIP()) {
		return false
	}

	if len(param.ID) > 0 && accSession.GetSessionID() != param.ID {
		return false
	}

	if len(param.User) > 0 && accSession.GetUserName() != param.User {
		return false
	}

	return true
}

//---------------------------------------------------------------------------------------

func (thisPt *cAuthenticationManager) RegisterAccSession(session common.IAccountingSession) {
	thisPt.sessionsLock.Lock()
	defer thisPt.sessionsLock.Unlock()

	//add users
	thisPt.sessions[session.GetSessionID()] = session
	thisPt.users[session.GetUserName()]++
}

//---------------------------------------------------------------------------------------

func (thisPt *cAuthenticationManager) RemoveAccSession(session common.IAccountingSession) {
	thisPt.sessionsLock.Lock()
	defer thisPt.sessionsLock.Unlock()

	delete(thisPt.sessions, session.GetSessionID())

	//
	count := thisPt.users[session.GetUserName()]
	if count > 1 {
		thisPt.users[session.GetUserName()]--
	} else {
		delete(thisPt.users, session.GetUserName())
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *cAuthenticationManager) OnListUsersCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {
	searchParam := params.(sAuthenticationManagerListUsersParams)

	type userInfo struct {
		UserName string `json:"user_name"`
		Sessions uint32 `json:"sessions"`
	}

	userList := []userInfo{}

	thisPt.sessionsLock.RLock()
	defer thisPt.sessionsLock.RUnlock()

	//list users
	for k, v := range thisPt.users {
		if len(searchParam.User) > 0 && k != searchParam.User {
			continue
		}
		userList = append(userList, userInfo{UserName: k, Sessions: v})
	}
	return thisPt.params.Utils.CreateHttpResponseFromObject(userList)
}

//---------------------------------------------------------------------------------------
func (thisPt *cAuthenticationManager) OnListCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {

	searchParam := thisPt.prepareSearchParam(params)

	//sort function
	sortCallBack := func(key string, item interface{}) uint64 {
		session := item.(common.IAccountingSession)
		return session.GetTransfer().GetValue(key)
	}

	//create sorter
	sorter := thisPt.params.Utils.CreateHeapSorter(common.MAXCOMMANDRESPONSEITEMS, sortCallBack, searchParam.Sort)

	thisPt.sessionsLock.RLock()
	defer thisPt.sessionsLock.RUnlock()

	//session
	for _, v := range thisPt.sessions {
		if thisPt.matchSession(v, searchParam) {
			sorter.AddItem(v)
		}
	}

	return thisPt.params.Utils.CreateHttpResponseFromString(sorter.ToJson())
}

//---------------------------------------------------------------------------------------
func (thisPt *cAuthenticationManager) OnStatus(req *http.Request, params interface{}) (common.IHTTPResponse, error) {
	thisPt.sessionsLock.RLock()
	defer thisPt.sessionsLock.RUnlock()

	thisPt.stat.SessionsCount = uint64(len(thisPt.sessions))
	thisPt.stat.UsersCount = uint64(len(thisPt.users))
	return thisPt.params.Utils.CreateHttpResponseFromObject(thisPt.stat)
}

//---------------------------------------------------------------------------------------
func (thisPt *cAuthenticationManager) OnDCCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {

	searchParam := thisPt.prepareSearchParam(params)

	thisPt.sessionsLock.Lock()
	defer thisPt.sessionsLock.Unlock()

	//search and DC
	for k, v := range thisPt.sessions {
		if thisPt.matchSession(v, searchParam) {
			v.Stop()
			delete(thisPt.sessions, k)
		}
	}

	return thisPt.params.Utils.CreateHttpResponseFromString("OK")
}

//---------------------------------------------------------------------------------------

//GetAccountingSession for IAuthenticationManger
func (thisPt *cAuthenticationManager) GetAccountingSession(sessionID string, accessFunc common.TAccessFunction) error {
	thisPt.sessionsLock.RLock()
	defer thisPt.sessionsLock.RUnlock()
	session := thisPt.sessions[sessionID]
	if session != nil {
		accessFunc(session)
		return nil
	}
	return errors.New("invalid session ID")
}

//---------------------------------------------------------------------------------------

//GetAuthenticator for IAuthenticationManger
func (thisPt *cAuthenticationManager) GetAuthenticator(typeName string) common.IAuthenticator {
	thisPt.authLocks.RLock()
	defer thisPt.authLocks.RUnlock()
	for _, auth := range thisPt.authenticators {
		if auth.GetType() == typeName {
			return auth
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------

//RegisterDummyAuthenticator for IAuthenticationManger
func (thisPt *cAuthenticationManager) RegisterDummyAuthenticator(cfgFile string) error {
	auth := new(cDummyAuthenticator)
	auth.init(thisPt, thisPt.params.Utils, cfgFile)
	return thisPt.registerAuthenticator(auth)
}

//---------------------------------------------------------------------------------------

//AuthenticateUser for IAuthenticationManger
func (thisPt *cAuthenticationManager) AuthenticateUser(info common.SAuthenticationInfo) (common.IAuthenticator, error) {
	thisPt.authLocks.RLock()
	defer thisPt.authLocks.RUnlock()

	atomic.AddUint64(&thisPt.stat.LoginReqCount, 1)

	for _, auth := range thisPt.authenticators {
		if err := auth.AuthenticateUser(info); err == nil {
			return auth, nil
		}
	}

	atomic.AddUint64(&thisPt.stat.LoginFailCount, 1)
	log.Printf("authentication failed for user %s from ip %s\n", info.User, info.IP.String())
	return nil, errors.New("invalid user name or password ")
}

//---------------------------------------------------------------------------------------

//AuthenticateUser for IAuthenticationManger
func (thisPt *cAuthenticationManager) SetDummyInfo(userPass string, adminPass string) {
	auth := thisPt.GetAuthenticator("dummy")
	if auth == nil {
		return
	}

	dummy := auth.(*cDummyAuthenticator)
	dummy.ChangePasswords(adminPass, userPass)
}

//---------------------------------------------------------------------------------------

//AuthenticateUser for IAuthenticationManger
func (thisPt *cAuthenticationManager) AuthenticateAdmin(info common.SAuthenticationInfo) (common.IAuthenticator, int, error) {
	thisPt.authLocks.RLock()
	defer thisPt.authLocks.RUnlock()

	atomic.AddUint64(&thisPt.stat.AdminLoginCount, 1)

	for _, auth := range thisPt.authenticators {
		if adType, err := auth.AuthenticateAdmin(info); err == nil {
			return auth, adType, nil
		}
	}

	atomic.AddUint64(&thisPt.stat.AdminLoginFailCount, 1)
	log.Printf("admin authentication failed for user %s from ip %s\n", info.User, info.IP.String())
	return nil, 0, errors.New("invalid user name or password ")
}

//---------------------------------------------------------------------------------------

//SetCommander for IAuthenticationManger
func (thisPt *cAuthenticationManager) SetCommander(commander common.ICommander) {
	thisPt.params.Commander = commander

	selector := thisPt.params.Commander.CreateSelector()
	selector.Register("acc_sessions_list", thisPt.OnListCommand, sAuthenticationManagerListParams{})
	selector.Register("acc_users_list", thisPt.OnListUsersCommand, sAuthenticationManagerListUsersParams{})
	selector.Register("acc_sessions_dc", thisPt.OnDCCommand, sAuthenticationManagerListParams{})
	selector.Register("acc_sessions_status", thisPt.OnStatus, nil)
}

//---------------------------------------------------------------------------------------

//init
func (thisPt *cAuthenticationManager) init(params SAuthenticationManagerParams) {
	thisPt.params = params
	thisPt.sessions = make(map[string]common.IAccountingSession)
}

//---------------------------------------------------------------------------------------

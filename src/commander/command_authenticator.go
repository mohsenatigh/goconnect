package commander

import (
	"errors"
	"fmt"
	"goconnect/common"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const sessionsSegmentCount = 16000

//---------------------------------------------------------------------------------------
type sLoginCommandLoginParams struct {
	User     string `help:"user name" schema:"user" validate:"min=3,max=64,alphanum"`
	Password string `help:"password" schema:"password" validate:"min=6,max=64"`
}

//---------------------------------------------------------------------------------------
const loginTockenMagic = 0x1122736172617788

type sLoginClientToken struct {
	ID    uint64 `json:"id"`
	Salt  string `json:"salt"`
	Magic uint64 `json:"magic"`
}

//---------------------------------------------------------------------------------------
type sLoginTokenInternal struct {
	Username   string
	CreateTime int64
	LoginIp    string
	Flag       int
}

//---------------------------------------------------------------------------------------

type sCommandAuthenticatorParams struct {
	Utils              common.IUtils
	Authenticator      common.IAuthenticationManger
	Commander          common.ICommander
	TokenMaxLifeTime   int64
	LoginFailCount     uint32
	LoginFailTrackTime uint32
	MaintenanceHook    bool
}

//---------------------------------------------------------------------------------------
type cCommandAuthenticator struct {
	tokenHash        common.IHashLinkList
	loginFailTracker common.ILoginFailTracker
	params           sCommandAuthenticatorParams
	authKey          [32]byte
	authIV           [16]byte
}

//---------------------------------------------------------------------------------------
const (
	authCommandLogin      = "login"
	authCommandLogout     = "logout"
	authCommandLoginAdmin = "login_admin"
)

var authNoLoginCommands = []string{authCommandLogin, authCommandLoginAdmin}

//---------------------------------------------------------------------------------------
func (thisPt *cCommandAuthenticator) checkTokensForRemove(cTime int64) {
	if cTime == 0 {
		cTime = time.Now().Unix()
	}
	thisPt.tokenHash.CheckForTimeOut(nil, nil, cTime)
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommandAuthenticator) getClientInfo(id uint64) *sLoginTokenInternal {

	if info := thisPt.tokenHash.Find(id, nil, nil); info != nil {
		return info.(*sLoginTokenInternal)
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommandAuthenticator) createToken(userName string, ip string, flag int) (uint64, string) {
	cInfo := sLoginClientToken{}

	//fill clinet side info
	cInfo.ID = thisPt.params.Utils.GetUniqID()
	cInfo.Magic = loginTockenMagic
	cInfo.Salt = thisPt.params.Utils.GetRandomString(16)

	//create service side Info
	sInfo := new(sLoginTokenInternal)
	sInfo.CreateTime = time.Now().Unix()
	sInfo.LoginIp = ip
	sInfo.Username = userName

	//add to track list
	thisPt.tokenHash.Add(cInfo.ID, sInfo)

	//encrypt item
	return cInfo.ID, thisPt.params.Utils.EncryptData(thisPt.authKey[0:], thisPt.authIV[0:], &cInfo)
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommandAuthenticator) checkToken(ip string, token string) (uint64, error) {
	//check token length
	if len(token) < 16 {
		return 0, errors.New("invalid token")
	}

	//decrypt token
	cToken := sLoginClientToken{}
	if err := thisPt.params.Utils.DecryptData(thisPt.authKey[0:], thisPt.authIV[0:], token, &cToken); err != nil {
		return 0, err
	}

	//check magic
	if cToken.Magic != loginTockenMagic {
		return 0, errors.New("invalid token magic")
	}

	//check internl info
	intInfo := thisPt.getClientInfo(cToken.ID)
	if intInfo == nil {
		return 0, errors.New("invalid token")
	}

	//check creation IP
	if intInfo.LoginIp != ip {
		return 0, errors.New("invalid token ip")
	}

	//check for expiration
	cTime := time.Now().Unix()
	if cTime-intInfo.CreateTime > thisPt.params.TokenMaxLifeTime {
		return 0, errors.New("token expired")
	}

	return cToken.ID, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommandAuthenticator) handleLogin(ip string, param *sLoginCommandLoginParams, admin bool) (common.IHTTPResponse, error) {

	//fill auth info
	authInfo := common.SAuthenticationInfo{}
	authInfo.IP = net.ParseIP(ip)
	authInfo.Password = param.Password
	authInfo.User = param.User

	//result struct
	type loginResult struct {
		Token string `json:"token"`
		Msg   string `json:"msg"`
	}

	//
	result := loginResult{}

	//convert loginResult to json and create http response object
	returnResult := func() (common.IHTTPResponse, error) {
		resp := thisPt.params.Utils.CreateHttpResponse()
		resp.WriteJson(&result)

		//check token
		if len(result.Token) > 0 {
			resp.Header().Add("Set-Cookie", fmt.Sprintf("token=%s; Secure;", result.Token))
		} else {
			resp.WriteHeader(401)
		}

		//return response
		return resp, nil
	}

	//check for blocked IP
	if thisPt.loginFailTracker.CanLogin(ip) == false {
		result.Msg = "ip blocked"
		log.Printf("blocked IP %s", ip)
		return returnResult()
	}

	//authentication
	var err error
	var flag int
	if admin {
		_, flag, err = thisPt.params.Authenticator.AuthenticateAdmin(authInfo)
	} else {
		_, err = thisPt.params.Authenticator.AuthenticateUser(authInfo)
	}

	//invalid user name or password
	if err != nil {
		result.Msg = "invalid user name or password"
		thisPt.loginFailTracker.RegisterFail(ip)
		return returnResult()
	}

	//create token
	_, result.Token = thisPt.createToken(param.User, ip, flag)

	return returnResult()
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommandAuthenticator) handleLogout(ip string, req *http.Request) (common.IHTTPResponse, error) {

	//get client token
	token, err := thisPt.getTokenString(req)
	if err != nil {
		return nil, err
	}

	//token ID
	id, err := thisPt.checkToken(ip, token)
	if err != nil {
		return nil, err
	}

	//remove token
	thisPt.tokenHash.Remove(id, nil, nil)

	//return response
	resp := thisPt.params.Utils.CreateHttpResponse()
	resp.Header().Add("Set-Cookie", "token=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
	resp.Write([]byte("{ok}"))
	return resp, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommandAuthenticator) OnCommand(api string, req *http.Request, params interface{}) (common.IHTTPResponse, error) {

	//get peer IP
	ip := thisPt.getPeerIP(req)

	//check commands
	if api == authCommandLogin || api == authCommandLoginAdmin {
		return thisPt.handleLogin(ip, params.(*sLoginCommandLoginParams), api == authCommandLoginAdmin)
	} else if api == authCommandLogout {
		return thisPt.handleLogout(ip, req)
	}
	return nil, errors.New("invalid command")
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommandAuthenticator) getTokenString(req *http.Request) (string, error) {
	token := req.FormValue("token")
	if token == "" {
		if tokenC, err := req.Cookie("token"); err == nil && tokenC != nil {
			token = tokenC.Value
			return token, nil
		}
	}
	return token, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommandAuthenticator) getPeerIP(req *http.Request) string {
	ip := "0.0.0.0"
	if parts := strings.Split(req.RemoteAddr, ":"); len(parts) > 1 {
		ip = parts[0]
	}
	return ip
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommandAuthenticator) IsValidRequest(api string, req *http.Request) error {

	//Only APIs that are valid without authentication
	needToken := true
	for _, cmd := range authNoLoginCommands {
		if cmd == api {
			needToken = false
			break
		}
	}

	//check for maintenance hook
	if thisPt.params.MaintenanceHook {
		cIp := thisPt.getPeerIP(req)
		if cIp == "127.0.0.1" || cIp == "0.0.0.0" {
			needToken = false
		}
	}

	//check for the token requirement
	if needToken == false {
		return nil
	}

	//read token from params or from cookie
	token, err := thisPt.getTokenString(req)
	if err != nil {
		return err
	}

	//extract IP
	ip := thisPt.getPeerIP(req)

	//validate token
	if _, err := thisPt.checkToken(ip, token); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommandAuthenticator) Init(params sCommandAuthenticatorParams) {

	//
	thisPt.params = params

	//generate cooki key
	thisPt.params.Utils.FillRandomBuffer(thisPt.authKey[0:])
	thisPt.params.Utils.FillRandomBuffer(thisPt.authIV[0:])

	//
	thisPt.tokenHash = thisPt.params.Utils.CreateHashLinkList(sessionsSegmentCount, uint64(params.TokenMaxLifeTime))
	thisPt.loginFailTracker = thisPt.params.Utils.CreateLoginFailTracker(params.LoginFailCount, params.LoginFailTrackTime)

	//register API
	thisPt.params.Commander.RegisterCommand(authCommandLogin, sLoginCommandLoginParams{}, thisPt)
	thisPt.params.Commander.RegisterCommand(authCommandLoginAdmin, sLoginCommandLoginParams{}, thisPt)
	thisPt.params.Commander.RegisterCommand(authCommandLogout, nil, thisPt)

	//dead sessions remove routine
	go func() {
		for {
			time.Sleep(10 * time.Millisecond)
			thisPt.checkTokensForRemove(0)
		}
	}()

}

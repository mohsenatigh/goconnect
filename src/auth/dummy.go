package auth

import (
	"errors"
	"fmt"
	"goconnect/common"
	"io/ioutil"
	"log"
	"strings"
)

type cDummyAuthenticator struct {
	randomPass      string
	randomAdminPass string
	util            common.IUtils
	accManager      *cAuthenticationManager
}

//---------------------------------------------------------------------------------------

//AuthenticateUser for AuthenticateUser
func (thisPt *cDummyAuthenticator) AuthenticateUser(info common.SAuthenticationInfo) error {
	if info.User == "dummy" && info.Password == thisPt.randomPass {
		return nil
	}
	return errors.New("invalid user name or password")
}

//---------------------------------------------------------------------------------------

//AuthenticateUser for AuthenticateUser
func (thisPt *cDummyAuthenticator) AuthenticateAdmin(info common.SAuthenticationInfo) (int, error) {
	if info.User == "admin" && info.Password == thisPt.randomAdminPass {
		return common.IAuthenticatorAdminTypeFull, nil
	}
	return common.IAuthenticatorAdminTypeFail, errors.New("invalid user name or password")
}

//---------------------------------------------------------------------------------------

//CreateAccountingSession for AuthenticateUser

func (thisPt *cDummyAuthenticator) CreateAccountingSession(info common.SAccountingInfo) common.IAccountingSession {
	acc := new(cAccountingSessionBase)
	acc.Init(thisPt.accManager, info, thisPt, thisPt.util)
	return acc
}

//---------------------------------------------------------------------------------------

//GetType for AuthenticateUser
func (thisPt *cDummyAuthenticator) GetType() string {
	return "dummy"
}

//---------------------------------------------------------------------------------------
func (thisPt *cDummyAuthenticator) ChangePasswords(adminPass string, userPass string) {
	thisPt.randomAdminPass = adminPass
	thisPt.randomPass = userPass
}

//---------------------------------------------------------------------------------------
func (thisPt *cDummyAuthenticator) init(accManager *cAuthenticationManager, util common.IUtils, cfgFile string) {
	defer func() {
		fmt.Printf("users can login with user dummy and password %s\nadmin can login with user admin and password %s\n", thisPt.randomPass, thisPt.randomAdminPass)
	}()

	//the cfg file length is zero
	thisPt.randomAdminPass = util.GetRandomString(12)
	thisPt.randomPass = util.GetRandomString(12)

	if len(cfgFile) == 0 {
		return
	}

	thisPt.util = util
	thisPt.accManager = accManager

	//first, trying to load already existing items
	if buf, err := ioutil.ReadFile(cfgFile); err == nil {
		lines := strings.Split(string(buf), "\n")
		if len(lines) == 2 {
			thisPt.randomAdminPass = lines[0]
			thisPt.randomPass = lines[1]
			return
		}
	}

	//generating new items
	out := fmt.Sprintf("%s\n%s\n", thisPt.randomAdminPass, thisPt.randomPass)
	if err := ioutil.WriteFile(cfgFile, []byte(out), 0); err != nil {
		log.Printf("can not create dummy pass code file  with error %v\n", err)
	}
}

//---------------------------------------------------------------------------------------

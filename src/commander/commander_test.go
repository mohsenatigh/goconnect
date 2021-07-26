package commander

import (
	"encoding/json"
	"fmt"
	"goconnect/auth"
	"goconnect/common"
	"goconnect/utils"
	"net/http"
	"testing"
	"time"
)

//---------------------------------------------------------------------------------------
func testAuthentication(t *testing.T) {
	commander := cCommander{}

	authParam := auth.SAuthenticationManagerParams{}
	params := SCommanderInitParams{}
	params.BindAddress = "0.0.0.0:4443"
	params.EnableSeprateManagemnet = true
	params.ServeStaticContents = true
	params.Utils = utils.Create()
	params.TokenMaxLifeTime = 1600

	authParam.Utils = params.Utils
	params.Authenticator = auth.Create(authParam)
	params.Authenticator.RegisterDummyAuthenticator("")
	params.Authenticator.SetDummyInfo("123456", "123456")
	params.StaticDataPath = "/tmp/"

	commander.Init(params)

	//check login
	sendRequest := func(query string, key string) string {
		req, _ := http.NewRequest("GET", query, nil)
		resp, err := commander.HandleCommand(req)
		if err != nil || resp == nil {
			return ""
		}

		//check status code
		if resp.GetRespose().StatusCode != 200 {
			return ""
		}

		var outBuffer [4096]byte
		jOut := make(map[string]interface{})

		//get body
		n, err := resp.GetRespose().Body.Read(outBuffer[0:])
		if err != nil {
			return ""
		}

		if len(key) > 0 {
			//parse it as json
			if err := json.Unmarshal(outBuffer[0:n], &jOut); err != nil {
				return ""
			}
			return jOut[key].(string)
		}

		return "OK"
	}

	//admin login test
	token := sendRequest("/login_admin?user=admin&password=123456", "token")
	if token == "" {
		t.Fatal("admin login test failed")
	}

	//get help with this token
	if sendRequest(fmt.Sprintf("/help?token=%s", token), "") != "OK" {
		t.Fatal("geting help failed")
	}

	//check logout
	if sendRequest(fmt.Sprintf("/logout?token=%s", token), "") != "OK" {
		t.Fatal("logout failed")
	}

	//get help with this token
	if sendRequest(fmt.Sprintf("/help?token=%s", token), "") == "OK" {
		t.Fatal("use of invalid token")
	}

	//
	if token = sendRequest("/login_admin?user=admin&password=123456", "token"); token == "" {
		t.Fatal("admin login test failed")
	}

	//check for remove
	for i := 0; i < sessionsSegmentCount; i++ {
		commander.accessValidator.checkTokensForRemove(time.Now().Unix() + params.TokenMaxLifeTime + 1)
	}

	//get help with this token
	if sendRequest(fmt.Sprintf("/help?token=%s", token), "") == "OK" {
		t.Fatal("token should be expired")
	}

	//check for login fail
	for i := 0; i < common.MAXAUTHFAILCOUNT; i++ {
		if token = sendRequest("/login_admin?user=admin&password=1234567", "token"); token != "" {
			t.Fatal("invalid token created")
		}
	}

	//account should be locked
	if token = sendRequest("/login_admin?user=admin&password=123456", "token"); token != "" {
		t.Fatal("brute force check failed")
	}

}

//---------------------------------------------------------------------------------------
func testFunctionality(t *testing.T) {
	commander := cCommander{}
	params := SCommanderInitParams{}
	params.BindAddress = "0.0.0.0:4443"
	params.EnableSeprateManagemnet = true
	params.ServeStaticContents = true
	params.Utils = utils.Create()
	params.StaticDataPath = "/tmp/"
	params.MaintenanceHook = true

	commander.Init(params)

	type sCommand struct {
		request string
		valid   bool
		code    int
	}

	//test commands
	commands := []sCommand{
		{request: "/static/../etc/passwd", valid: true, code: 400},
		{request: "/help", valid: true, code: 200},
		{request: "/help?api=help", valid: true, code: 200},
		{request: "/help/test?api=help", valid: true, code: 200},
		{request: "/help/test?api=none", valid: true, code: 200},
		{request: "/help?api=h", valid: false, code: 0},
		{request: "/invalid?api=h", valid: false, code: 0},
	}

	//
	for _, c := range commands {
		req, _ := http.NewRequest("GET", c.request, nil)
		resp, err := commander.HandleCommand(req)

		if (err == nil) != c.valid {
			t.Fatal(err)
		}

		if resp != nil {
			fmt.Printf("%s \n", string(resp.ToByte()))
			if resp.GetRespose().StatusCode != c.code {
				t.Fatal("invalid status code\n")
			}
		}
	}
}

//---------------------------------------------------------------------------------------
func TestCommander(t *testing.T) {
	testFunctionality(t)
	testAuthentication(t)
}

package commander

import (
	"crypto/tls"
	"errors"
	"goconnect/common"
	"log"
	"net"
	"net/http"
	"path"
	"reflect"
	"strings"
	"sync"

	pcre "github.com/gijsbers/go-pcre"
	"github.com/gorilla/schema"
)

//---------------------------------------------------------------------------------------
type sHelpCommandParams struct {
	Api string `help:"target api" schema:"api" validate:"omitempty,min=3,max=64,alphanum"`
}

//---------------------------------------------------------------------------------------
type SCommanderInitParams struct {
	BindAddress             string
	StaticDataPath          string
	ServeStaticContents     bool
	ValidClients            []string
	KeyFile                 string
	CertFile                string
	EnableSeprateManagemnet bool
	MaintenanceHook         bool
	TokenMaxLifeTime        int64
	Authenticator           common.IAuthenticationManger
	Utils                   common.IUtils
}

//---------------------------------------------------------------------------------------

type sCommanderObjects struct {
	Actor       common.ICommanderActor
	ParamObject interface{}
}

//---------------------------------------------------------------------------------------

type cCommander struct {
	params          SCommanderInitParams
	routes          map[string]sCommanderObjects
	lock            sync.RWMutex
	routeExtract    pcre.Regexp
	decoder         *schema.Decoder
	accessValidator *cCommandAuthenticator
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommander) loadCerts() tls.Certificate {
	cert, err := thisPt.params.Utils.LoadCerts(thisPt.params.CertFile, thisPt.params.KeyFile)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	return cert
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommander) getClientIP(req *http.Request) string {
	ipParts := strings.Split(req.RemoteAddr, ":")
	return ipParts[0]
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommander) createStaticFilePath(url string) string {

	if url == "/" {
		return path.Join(thisPt.params.StaticDataPath, "index.html")
	}

	url = strings.ReplaceAll(url, "..", "")
	return path.Join(thisPt.params.StaticDataPath, url)
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommander) handleStaticContents(req *http.Request) common.IHTTPResponse {

	if thisPt.params.ServeStaticContents == false {
		return nil
	}

	response := thisPt.params.Utils.CreateHttpResponse()
	filePath := thisPt.createStaticFilePath(req.URL.Path)
	http.ServeFile(response, req, filePath)
	return response
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommander) checkAccessList(req *http.Request) error {
	if len(thisPt.params.ValidClients) == 0 {
		return nil
	}

	clIp := thisPt.getClientIP(req)
	for _, c := range thisPt.params.ValidClients {
		if c == clIp {
			return nil
		}
	}

	return errors.New("access denied")
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommander) checkPermitions(api string, req *http.Request) error {

	if err := thisPt.accessValidator.IsValidRequest(api, req); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------

func (thisPt *cCommander) handleDynamicContents(path string, req *http.Request) (common.IHTTPResponse, error) {

	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	//find module
	object, fnd := thisPt.routes[path]
	if fnd == false {
		return nil, errors.New("invalid API")
	}

	//create parameters
	var params interface{}
	if object.ParamObject != nil {
		if err := req.ParseForm(); err != nil {
			return nil, err
		}

		//create a new instance of the parameter object
		nObject := reflect.New(reflect.TypeOf(object.ParamObject)).Elem()
		params = nObject.Addr().Interface()

		//get form data
		formData := req.Form
		if req.Method == http.MethodPost {
			formData = req.PostForm
		}

		if err := thisPt.decoder.Decode(params, formData); err != nil {
			return nil, err
		}

		//validate parameters
		if err := thisPt.params.Utils.ValidateStruct(nObject.Interface()); err != nil {
			return nil, err
		}
	}

	return object.Actor.OnCommand(path, req, params)
}

//---------------------------------------------------------------------------------------

//RegisterCommand for ICommander
func (thisPt *cCommander) RegisterCommand(path string, param interface{}, actor common.ICommanderActor) {

	thisPt.lock.Lock()
	defer thisPt.lock.Unlock()

	object := sCommanderObjects{}
	object.Actor = actor
	object.ParamObject = param

	//check for duplicate route registration
	if _, fnd := thisPt.routes[path]; fnd == true {
		log.Fatalf("duplicate route registration %s \n", path)
	}
	thisPt.routes[path] = object
}

//---------------------------------------------------------------------------------------

//HandleCommand for ICommander
func (thisPt *cCommander) HandleCommand(req *http.Request) (common.IHTTPResponse, error) {

	//extract path
	path := "/"
	matcher := thisPt.routeExtract.MatcherString(req.URL.Path, 0)
	if matcher != nil && matcher.Groups() > 0 {
		path = matcher.GroupString(1)
	}

	//check for access contrl
	if err := thisPt.checkAccessList(req); err != nil {
		return nil, err
	}

	//request for index
	if path == "" || path == "static" {
		return thisPt.handleStaticContents(req), nil
	}

	//check permitions
	if err := thisPt.checkPermitions(path, req); err != nil {
		return nil, err
	}

	return thisPt.handleDynamicContents(path, req)
}

//---------------------------------------------------------------------------------------

//ServeHTTP for http.Handler
func (thisPt *cCommander) ServeHTTP(resWriter http.ResponseWriter, req *http.Request) {
	//handle command
	res, err := thisPt.HandleCommand(req)
	if err != nil {
		log.Printf("http command failed with error [%s] \n", err)
		resWriter.Write([]byte(""))
		return
	}

	//copy to http.ResponseWriter
	res.Copy(resWriter)
}

//---------------------------------------------------------------------------------------
func (thisPt *cCommander) handleHelpCommand(req *http.Request, params interface{}) (common.IHTTPResponse, error) {
	helpParam := params.(*sHelpCommandParams)
	thisPt.lock.RLock()
	defer thisPt.lock.RUnlock()

	//
	type sHelpResponse struct {
		Api  string `json:"Api"`
		Help string `json:"Help"`
	}

	//fill help objects
	list := []sHelpResponse{}
	for k, v := range thisPt.routes {
		if len(helpParam.Api) > 0 && helpParam.Api != k {
			continue
		}

		//get help
		help := ""
		if v.ParamObject != nil {
			help = thisPt.params.Utils.GetHelp(v.ParamObject)
		}
		list = append(list, sHelpResponse{Api: k, Help: help})
	}

	//create response
	response := thisPt.params.Utils.CreateHttpResponse()
	response.WriteJson(list)
	return response, nil
}

//---------------------------------------------------------------------------------------

//OnCommand for ICommanderActor
func (thisPt *cCommander) OnCommand(api string, req *http.Request, params interface{}) (common.IHTTPResponse, error) {
	if api == "help" {
		return thisPt.handleHelpCommand(req, params)
	}
	return nil, errors.New("invalid API call")
}

//---------------------------------------------------------------------------------------

//CreateSelector for ICommander
func (thisPt *cCommander) CreateSelector() common.ICommanderSelector {
	selector := new(cCommanderSelector)
	selector.Init(thisPt)
	return selector
}

//---------------------------------------------------------------------------------------

//
func (thisPt *cCommander) Init(params SCommanderInitParams) {
	//
	thisPt.params = params
	thisPt.routes = make(map[string]sCommanderObjects)
	thisPt.routeExtract = pcre.MustCompileJIT(`\/*(.*?)(?:$|\?|\/)`, 0, 0)
	thisPt.decoder = schema.NewDecoder()
	thisPt.decoder.IgnoreUnknownKeys(true)

	//register help path
	thisPt.RegisterCommand("help", sHelpCommandParams{}, thisPt)

	//checking for separate management channel
	if thisPt.params.EnableSeprateManagemnet == false {
		return
	}

	//init authenticator
	authParam := sCommandAuthenticatorParams{}
	authParam.Authenticator = thisPt.params.Authenticator
	authParam.Commander = thisPt
	authParam.LoginFailCount = common.MAXAUTHFAILCOUNT
	authParam.LoginFailTrackTime = common.MAXAUTHTRACKTIME
	authParam.MaintenanceHook = params.MaintenanceHook
	authParam.Utils = params.Utils
	authParam.TokenMaxLifeTime = params.TokenMaxLifeTime
	thisPt.accessValidator = new(cCommandAuthenticator)
	thisPt.accessValidator.Init(authParam)

	//create server
	go func() {
		server := &http.Server{Addr: thisPt.params.BindAddress, Handler: thisPt}
		config := &tls.Config{}
		config.NextProtos = []string{"http/1.1"}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = thisPt.loadCerts()
		ln, err := net.Listen("tcp", thisPt.params.BindAddress)
		if err != nil {
			log.Fatal(err)
		}
		tlsListener := tls.NewListener(ln, config)
		server.Serve(tlsListener)
	}()

}

//---------------------------------------------------------------------------------------

//Create ...
func Create(params SCommanderInitParams) common.ICommander {
	cmd := cCommander{}
	cmd.Init(params)
	return &cmd
}

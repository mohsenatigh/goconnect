package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"goconnect/common"
	"io/ioutil"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/go-playground/validator.v8"
)

//CUtils ..
type CUtils struct {
	counter    uint64
	validators struct {
		nameValidator regexp.Regexp
	}
}

//---------------------------------------------------------------------------------------

//CreateNewIPTrie for IUtils
func (thisPt *CUtils) CreateNewIPTrie(version int) common.IIPTrie {
	tri := new(cIPTrie)
	tri.Init(version)
	return tri
}

//---------------------------------------------------------------------------------------

//GetUniqID for IUtils
func (thisPt *CUtils) GetUniqID() uint64 {
	if thisPt.counter == 0 {
		thisPt.counter = mrand.Uint64()
	}
	thisPt.counter++
	return thisPt.counter
}

//---------------------------------------------------------------------------------------

//GetRandomString for IUtils
func (thisPt *CUtils) GetRandomString(size uint32) string {
	var letterRunes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, size)
	for i := range b {
		b[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}
	return string(b)
}

//---------------------------------------------------------------------------------------

//GetHexString for IUtils
func (thisPt *CUtils) GetHexString(num int) string {
	hexStr := [16]rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}
	result := []rune{'0', '0', '0', '0', '0', '0', '0', '0'}
	index := 7
	for index = 7; num > 0; index-- {
		val := num & 0xff
		num = num >> 4
		result[index] = hexStr[val]
	}
	return string(result[index:])
}

//---------------------------------------------------------------------------------------

//FillRandomBuffer for IUtils
func (thisPt *CUtils) FillRandomBuffer(buf []byte) {
	for i := range buf {
		buf[i] = byte(mrand.Intn(255))
	}
}

//---------------------------------------------------------------------------------------

//CreateLocalIPPool for IUtils
func (thisPt *CUtils) CreateLocalIPPool(start string, end string) common.IIPPool {
	ipPool := new(cIPPool)
	if ipPool.Init(start, end) == 0 {
		log.Fatalf("invalid pool range %s - %s \n", start, end)
	}
	return ipPool
}

//---------------------------------------------------------------------------------------

//CreateHashLinkList for IUtils
func (thisPt *CUtils) CreateHashLinkList(segmentCount uint32, inactveTimeOut uint64) common.IHashLinkList {
	list := new(cHashLinkList)
	list.Init(int(segmentCount), int64(inactveTimeOut))
	return list
}

//---------------------------------------------------------------------------------------

//CreateBuffer for IUtils
func (thisPt *CUtils) CreateBuffer(len uint32) common.IBuffer {
	buffer := new(cBuffer)
	buffer.Init(len)
	return buffer
}

//---------------------------------------------------------------------------------------

//EncryptData data
func (thisPt *CUtils) EncryptData(key []byte, iv []byte, data interface{}) string {

	//convert data to json
	jval, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	//encrypt jval
	aes, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	cfb := cipher.NewCFBEncrypter(aes, iv)
	out := make([]byte, len(jval))
	cfb.XORKeyStream(out, []byte(jval))

	//convert to base64
	bout := base64.URLEncoding.EncodeToString(out)

	return bout
}

//---------------------------------------------------------------------------------------

//ParseJSONC data
func (thisPt *CUtils) ParseJSONC(json string) string {
	var re = regexp.MustCompile(`(?m)\/\*.*?\*\/`)
	return re.ReplaceAllString(json, "")
}

//---------------------------------------------------------------------------------------

//DecryptData for IUtils
func (thisPt *CUtils) DecryptData(key []byte, iv []byte, in string, data interface{}) error {

	//decode from base64
	bout, err := base64.URLEncoding.DecodeString(in)
	if err != nil {
		return err
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	cfb := cipher.NewCFBDecrypter(aes, iv)

	out := make([]byte, len(bout))
	cfb.XORKeyStream(out, bout)

	//load object
	if err = json.Unmarshal(out, data); err != nil {
		return err
	}
	return nil
}

//---------------------------------------------------------------------------------------

//IsValidName for IUtils
func (thisPt *CUtils) IsValidName(name string) bool {
	re := regexp.MustCompile(`^(?=[a-zA-Z0-9._]{2,40}$)(?!.*[_.]{2})[^_.].*[^_.]$`)
	return re.Match([]byte(name))
}

//---------------------------------------------------------------------------------------

//GetHelp for IUtils
func (thisPt *CUtils) GetHelp(input interface{}) string {
	//Try to find the related JSON field
	help := ""
	eType := reflect.TypeOf(input)
	for i := 0; i < eType.NumField(); i++ {
		f := eType.Field(i)
		hStr := f.Tag.Get("help")
		param := f.Tag.Get("schema")
		if len(hStr) > 0 {
			if i > 0 {
				help += " , "
			}
			if len(param) > 0 {
				hStr = param + " : " + hStr
			}
			help += hStr
		}
	}
	return help
}

//---------------------------------------------------------------------------------------

//ValidateStruct for IUtils
func (thisPt *CUtils) ValidateStruct(input interface{}) error {

	//translate error
	translateError := func(err error) error {
		//
		var re = regexp.MustCompile(`(?m)json:"(.*?)"`)
		errF := err.(validator.ValidationErrors)

		//Try to find the related JSON field
		for _, v := range errF {
			errString := ""
			names := strings.Split(v.NameNamespace, ".")
			typeOf := reflect.TypeOf(input)
			fObj, _ := typeOf.FieldByName(names[0])
			for _, n := range names[1:] {
				fObj, _ = fObj.Type.FieldByName(n)
			}
			out := re.FindAllStringSubmatch(string(fObj.Tag), 1)
			if len(out) > 0 {
				errString = fmt.Sprintf("invalid value for %s ", out[0][1])
			} else {
				errString = fmt.Sprintf("invalid value for %s ", v.NameNamespace)
			}
			return errors.New(errString)
		}
		return nil
	}

	//routes validator
	checkRoutes := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		const maxRoutes = 256
		list, valid := field.Interface().([]string)
		if !valid {
			return false
		}

		if len(list) > maxRoutes {
			return false
		}

		for _, ipVal := range list {
			if _, _, err := net.ParseCIDR(ipVal); err != nil {
				return false
			}
		}
		return true
	}

	//IP list validator
	addressListValidator := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		const maxIPAddress = 32
		list, valid := field.Interface().([]string)
		if !valid {
			return false
		}

		if len(list) > maxIPAddress {
			return false
		}

		for _, ipVal := range list {
			if ip := net.ParseIP(ipVal); ip == nil {
				return false
			}
		}
		return true
	}

	//IP range validator
	ipRangeValidator := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		addressRange, valid := field.Interface().(string)
		if !valid {
			return false
		}

		items := strings.Split(addressRange, "-")
		if len(items) != 2 {
			return false
		}

		sIp := net.ParseIP(items[0])
		dIp := net.ParseIP(items[1])

		if sIp == nil || dIp == nil {
			return false
		}

		if len(sIp) != len(dIp) {
			return false
		}

		return true
	}

	//name validation
	isValidName := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		name, valid := field.Interface().(string)
		if !valid {
			return false
		}

		if l := len(name); l < 3 || l > 64 {
			return false
		}

		if strings.ContainsAny(name, "*^~|%><[]\"'") {
			return false
		}

		return true
	}

	//time validation
	isValidTime := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		time, valid := field.Interface().(string)
		if !valid {
			return false
		}
		re := regexp.MustCompile(`(?m)[0-2][0-9]:[0-9][0-9]`)
		return re.Match([]byte(time))
	}

	//day validation
	isValidDay := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		day, valid := field.Interface().(string)
		if !valid {
			return false
		}
		re := regexp.MustCompile(`(?m)^(mo|tu|we|th|fr|sa|su)$`)
		return re.Match([]byte(day))
	}

	//validate
	config := &validator.Config{TagName: "validate"}
	validate := validator.New(config)
	validate.RegisterValidation("routes", checkRoutes)
	validate.RegisterValidation("iplist", addressListValidator)
	validate.RegisterValidation("iprange", ipRangeValidator)
	validate.RegisterValidation("name", isValidName)
	validate.RegisterValidation("time", isValidTime)
	validate.RegisterValidation("day", isValidDay)

	err := validate.Struct(input)
	if err != nil {
		return translateError(err)
	}
	return nil
}

//---------------------------------------------------------------------------------------

//GenerateCert for IUtils
func (thisPt *CUtils) GenerateCert() (string, string, error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	notBefore := time.Now()
	notAfter := notBefore.Add((24 * 365) * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"goconnect"},
			Country:      []string{"germany"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"goconnect.io"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	certOut := bytes.NewBufferString("")
	keyOut := bytes.NewBufferString("")

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", err
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return "", "", err
	}

	return certOut.String(), keyOut.String(), nil
}

//---------------------------------------------------------------------------------------

//LoadCerts for IUt
func (thisPt *CUtils) LoadJsonFile(fileName string) (string, error) {
	const maxFileSize = common.MAXCONFIGFILESIZE

	stInfo, err := os.Stat(fileName)
	if err != nil {
		return "", err
	}

	if stInfo.Size() > maxFileSize {
		return "", errors.New("invalid file size")
	}

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}

	dataStr := string(data)

	ext := filepath.Ext(fileName)
	if ext == ".jsonc" {
		dataStr = thisPt.ParseJSONC(dataStr)
	}
	return dataStr, nil
}

//---------------------------------------------------------------------------------------

//LoadCerts for IUtils
func (thisPt *CUtils) LoadCerts(certFile string, keyFile string) (tls.Certificate, error) {

	if len(certFile) > 0 {
		if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
			return cert, nil
		} else {
			return tls.Certificate{}, err
		}
	}

	certPem, keyPem, err := thisPt.GenerateCert()
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair([]byte(certPem), []byte(keyPem))
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

//---------------------------------------------------------------------------------------

//CreateLoginFailTracker for IUtils
func (thisPt *CUtils) CreateLoginFailTracker(failCount uint32, maxTrackTime uint32) common.ILoginFailTracker {
	tracker := new(cLoginFailTracker)
	tracker.Init(thisPt, maxTrackTime, failCount)
	return tracker
}

//---------------------------------------------------------------------------------------

//CreateHttpResponse for IUtils
func (thisPt *CUtils) CreateHttpResponse() common.IHTTPResponse {
	//We have different type of channels for the HTTP response.
	//so itis better to create a limited HTTP response buffer

	const maxHttpResponseBuffer = 40960000
	object := new(cHttpResponse)
	object.Init(maxHttpResponseBuffer)
	return object
}

//---------------------------------------------------------------------------------------

//CreateHttpResponse for IUtils
func (thisPt *CUtils) CreateHttpResponseFromObject(object interface{}) (common.IHTTPResponse, error) {
	resp := thisPt.CreateHttpResponse()
	if err := resp.WriteJson(object); err != nil {
		return nil, err
	}
	return resp, nil
}

//---------------------------------------------------------------------------------------

//CreateHttpResponse for IUtils
func (thisPt *CUtils) CreateHttpResponseFromBuffer(buffer []byte) (common.IHTTPResponse, error) {
	resp := thisPt.CreateHttpResponse()
	if _, err := resp.Write(buffer); err != nil {
		return nil, err
	}
	return resp, nil
}

//---------------------------------------------------------------------------------------

//CreateHttpResponse for IUtils
func (thisPt *CUtils) CreateHttpResponseFromString(buffer string) (common.IHTTPResponse, error) {
	return thisPt.CreateHttpResponseFromBuffer([]byte(buffer))
}

//---------------------------------------------------------------------------------------

//CreateHeapSorter for IUtils
func (thisPt *CUtils) CreateHeapSorter(itemsCount uint32, callback common.THeapSorterCallBackFunc, param string) common.IHeapSorter {
	heapS := new(cHeapSorter)
	heapS.Init(itemsCount, callback, param)
	return heapS
}

//---------------------------------------------------------------------------------------

//CastJson for IUtils
func (thisPt *CUtils) CastJsonObject(in interface{}, out interface{}) error {

	//convert map to struct
	cfg := mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   out,
		TagName:  "json",
	}

	//convert to data
	decoder, err := mapstructure.NewDecoder(&cfg)
	if err != nil {
		return err
	}

	if err := decoder.Decode(in); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------

//Create ...
func Create() common.IUtils {
	utility := new(CUtils)
	return utility
}

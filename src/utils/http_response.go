package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

//---------------------------------------------------------------------------------------
type cHttpResponse struct {
	response http.Response
	buffer   cHttpResponseBuffer
}

//---------------------------------------------------------------------------------------

//Header ResponseWriter,IHTTPResponse
func (thisPt *cHttpResponse) Header() http.Header {
	return thisPt.response.Header
}

//---------------------------------------------------------------------------------------

// Write ResponseWriter,IHTTPResponse
func (thisPt *cHttpResponse) Write(data []byte) (int, error) {
	wlen, err := thisPt.buffer.Write(data)
	if err != nil {
		return 0, err
	}
	thisPt.response.ContentLength += int64(len(data))
	return wlen, err
}

//---------------------------------------------------------------------------------------

// WriteJson for IHTTPResponse
func (thisPt *cHttpResponse) WriteJson(data interface{}) error {
	jval, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return err
	}
	if _, err = thisPt.Write(jval); err != nil {
		return err
	}
	return nil
}

//---------------------------------------------------------------------------------------

//WriteHeader for ResponseWriter,IHTTPResponse
func (thisPt *cHttpResponse) WriteHeader(statusCode int) {
	thisPt.response.StatusCode = statusCode
}

//---------------------------------------------------------------------------------------

//GetRespose for IHTTPResponse
func (thisPt *cHttpResponse) GetRespose() http.Response {
	return thisPt.response
}

//---------------------------------------------------------------------------------------

//ToByte for IHTTPResponse
func (thisPt *cHttpResponse) ToByte() []byte {
	buff := bytes.NewBuffer(nil)
	thisPt.response.Write(buff)
	return buff.Bytes()
}

//---------------------------------------------------------------------------------------

//Copy for IHTTPResponse
func (thisPt *cHttpResponse) Copy(writer http.ResponseWriter) {
	writer.WriteHeader(thisPt.response.StatusCode)
	io.Copy(writer, thisPt.response.Body)
	for k, v := range thisPt.response.Header {
		for _, hV := range v {
			writer.Header().Add(k, hV)
		}
	}
	thisPt.response.Body.Close()
}

//---------------------------------------------------------------------------------------
func (thisPt *cHttpResponse) Init(maxBuffer uint32) {
	thisPt.response.ProtoMinor = 1
	thisPt.response.ProtoMajor = 1
	thisPt.response.StatusCode = 200
	thisPt.response.Header = make(map[string][]string)
	thisPt.buffer.Init(maxBuffer)

	thisPt.response.Body = &thisPt.buffer
}

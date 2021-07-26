package protocols

import (
	"bufio"
	"bytes"
	"goconnect/utils"
	"net/http"
	"strings"
	"testing"
)

//---------------------------------------------------------------------------------------
func testCookies(t *testing.T) {

	key := sSSLVpnServerKeyCookie{}
	out := sSSLVpnServerKeyCookie{}

	server := cSSLVpnServer{}
	util := utils.Create()
	server.params.Utils = util

	util.FillRandomBuffer(server.encKey[0:])
	util.FillRandomBuffer(server.encIV[0:])

	key.ClientIP = "192.168.1.1"
	key.RandomCounter = 1
	key.UserName = "test"
	key.VirtaulIP = "172.16.0.1"
	key.Magic = sslVpnCookieMagic
	keyOut := server.generateKeyCookie(key)

	keyOutStrSeg := strings.Split(keyOut, "=")

	out, res := server.decodeKeyCookie(keyOutStrSeg[1])
	if res == false || out.ClientIP != key.ClientIP || out.UserName != key.UserName {
		t.Fatalf("can not decode key")
	}

}

//---------------------------------------------------------------------------------------
func testHTTPAuth(t *testing.T) {

	type testRequest struct {
		req            string
		expectedResult bool
	}

	//Create server objct
	server := cSSLVpnServer{}
	server.params.Utils = utils.Create()

	sampleRequests := []testRequest{
		{
			req: "POST /auth HTTP/1.1\r\n" +
				"Host: 192.168.56.1\r\n" +
				"User-Agent: Open AnyConnect VPN Agent v8.05-1\r\n" +
				"Cookie: webvpncontext=kfpE5LevJQWPOm4Xtm4dq_5VBvDx2hrELKHihYFu254ijLF7j1HVVucKlsFcV7ELRULzL0DSLHrsBvNBjRN2nm-4VvAILEMwjmc1fh3SjGtQu0oxsJfkPkghDNrCj9SsXg==\r\n" +
				"Accept: */*\r\n" +
				"Accept-Encoding: identity\r\n" +
				"X-Transcend-Version: 1\r\n" +
				"X-Aggregate-Auth: 1\r\n" +
				"X-AnyConnect-Platform: linux-64\r\n" +
				"X-Support-HTTP-Auth: true\r\n" +
				"X-Pad: 0000000000000000000\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 237\r\n\r\n" +
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
				"<config-auth client=\"vpn\" type=\"auth-reply\"><version who=\"vpn\">v8.05-1</version><device-id>linux-64</device-id><auth><username>dummy</username><password>YvSgD5xAV0YU</password></auth></config-auth>\r\n",
			expectedResult: true,
		},
		{
			req: "POST /auth HTTP/1.1\r\n" +
				"Cache-Control: no-cache\r\n" +
				"Connection: Close\r\n" +
				"Pragma: no-cache\r\n" +
				"Cookie: webvpncontext=auth;\r\n" +
				"User-Agent: AnyConnect Windows 4.5.03040\r\n" +
				"X-Transcend-Version: 1\r\n" +
				"X-Aggregate-Auth: 1\r\n" +
				"X-AnyConnect-Platform: win\r\n" +
				"Content-Length: 27\r\n\r\n" +
				"password=test&username=test\r\n",
			expectedResult: true,
		},
		{
			req: "POST /auth HTTP/1.1\r\n" +
				"Cache-Control: no-cache\r\n" +
				"Connection: Close\r\n" +
				"Pragma: no-cache\r\n" +
				"Cookie: webvpncontext=auth;\r\n" +
				"User-Agent: AnyConnect Windows 4.5.03040\r\n" +
				"X-Transcend-Version: 1\r\n" +
				"X-Aggregate-Auth: 1\r\n" +
				"X-AnyConnect-Platform: win\r\n" +
				"Content-Length: 27\r\n\r\n" +
				"password=test&username=te\r\n",
			expectedResult: false,
		},
	}

	for _, resSample := range sampleRequests {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(resSample.req))))
		if err != nil {
			t.Fatalf("%v", err)
		}

		if _, res := server.parseAuthForm(req); res != resSample.expectedResult {
			t.Fatalf("auth test failed for %v", req)
		}
	}

}

//---------------------------------------------------------------------------------------
func testHTTPRead(t *testing.T) {
	const testCount = 2
	util := utils.Create()
	post :=
		"POST / HTTP/1.1\r\n" +
			"Host: 192.168.56.1\r\n" +
			"User-Agent: Open AnyConnect VPN Agent v8.05-1\r\n" +
			"Accept: #//#\r\n" +
			"Accept-Encoding: identity\r\n" +
			"X-Transcend-Version: 1\r\n" +
			"X-Aggregate-Auth: 1\r\n" +
			"X-AnyConnect-Platform: linux-64\r\n" +
			"X-Support-HTTP-Auth: true\r\n" +
			"X-Pad: 000000000000000000000000000000000000000000000000\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 206\r\n\r\n"

	body := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
		"<config-auth client=\"vpn\" type=\"init\">" +
		"<version who=\"vpn\">v8.05-1</version>" +
		"<device-id>linux-64</device-id>" +
		"<group-access>https://192.168.56.1</group-access></config-auth>"

	buffer := util.CreateBuffer(4096)
	buffer.Write([]byte(post))

	server := cSSLVpnServer{}

	//header only
	if server.readHTTP(buffer) != nil {
		t.Fatalf("http request process failed \n")
	}

	//header + body
	buffer.Write([]byte(body))
	if server.readHTTP(buffer) == nil {
		t.Fatalf("http request process failed \n")
	}

	//test multi-request
	buffer.Reset()
	for i := 0; i < testCount; i++ {
		buffer.Write([]byte(post))
		buffer.Write([]byte(body))
	}

	for i := 0; i < testCount; i++ {
		if server.readHTTP(buffer) == nil {
			t.Fatalf("http request process failed \n")
		}
	}

	//
	if server.readHTTP(buffer) != nil {
		t.Fatalf(" invalid request\n")
	}

	//test connect
	connect :=
		"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
			"Host: 192.168.56.1\r\n" +
			"User-Agent: Open AnyConnect VPN Agent v8.05-1\r\n" +
			"Cookie: webvpn=vZB1ducjCqDnvRmQS1GOMFLq0AtnU5JJ3KXZYKMN4m0=\r\n" +
			"X-CSTP-Version: 1\r\n" +
			"X-CSTP-Hostname: test-server\r\n" +
			"X-CSTP-Accept-Encoding: oc-lz4,lzs\r\n" +
			"X-CSTP-Base-MTU: 1500\r\n" +
			"X-CSTP-MTU: 1390\r\n" +
			"X-CSTP-Address-Type: IPv6,IPv4\r\n" +
			"X-CSTP-Full-IPv6-Capability: true\r\n" +
			"X-DTLS-Master-Secret: D875DDFE027F7B4A239DF085C8A437FB24403A3DBAE5477FB5CD3D203C7031C051C89FE311E387758B74E29F93E6E9B5\r\n" +
			"X-DTLS-CipherSuite:\r\n" +
			"PSK-NEGOTIATE:OC-DTLS1_2-AES256-GCM:OC2-DTLS1_2-CHACHA20-POLY1305:OC-DTLS1_2-AES128-GCM:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA\r\n" +
			"X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256\r\n" +
			"X-DTLS-Accept-Encoding: oc-lz4,lzs\r\n\r\n"

	buffer.Reset()
	buffer.Write([]byte(connect))

	//
	if server.readHTTP(buffer) == nil {
		t.Fatalf("can not read connect request\n")
	}

	//
}

//---------------------------------------------------------------------------------------
func TestSSL(t *testing.T) {
	testCookies(t)
	testHTTPAuth(t)
	testHTTPRead(t)
}

//---------------------------------------------------------------------------------------

package protocols

import "log"

//---------------------------------------------------------------------------------------

//CreateTunInterface ...
func CreateTunInterface(params STunInitParams) {
	tun := new(cTun)
	if err := tun.Init(params); err != nil {
		log.Fatalln(err)
	}
}

//---------------------------------------------------------------------------------------

//CreateSSLVPN ...
func CreateSSLVPN(params SSSLVpnInitParams) {
	ssl := new(cSSLVpnServer)
	if err := ssl.Init(params); err != nil {
		log.Fatalln(err)
	}
}

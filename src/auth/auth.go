package auth

import "goconnect/common"

//---------------------------------------------------------------------------------------

//Create Auth manager object
func Create(params SAuthenticationManagerParams) common.IAuthenticationManger {
	authMan := new(cAuthenticationManager)
	authMan.init(params)
	return authMan
}

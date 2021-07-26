package utils

import (
	"testing"
)

//test data structure
type testData struct {
	F1 uint32 `help:"f1 help" schema:"f1"`
	F2 uint32 `help:"f2 help" schema:"f2"`
	F3 uint32 `help:"f3 help" schema:"f3"`
	F4 uint32 `help:"f4 help" schema:"f4"`
}

//---------------------------------------------------------------------------------------
func testCrypto(t *testing.T) {
	test := testData{}
	testOut := testData{}
	test.F1 = 1
	test.F2 = 2
	test.F3 = 3
	test.F4 = 4

	utils := CUtils{}

	key := [32]byte{}
	iv := [16]byte{}

	utils.FillRandomBuffer(key[0:])
	utils.FillRandomBuffer(iv[0:])

	encOut := utils.EncryptData(key[0:], iv[0:], &test)
	if len(encOut) == 0 {
		t.Fatalf("encryption test failed \n")
	}

	if utils.DecryptData(key[0:], iv[0:], encOut, &testOut) != nil {
		t.Fatalf("decryption test failed \n")
	}

	if testOut.F4 != test.F4 {
		t.Fatalf("decryption test failed \n")
	}

}

//---------------------------------------------------------------------------------------
func testCertificate(t *testing.T) {
	utils := CUtils{}

	cert, key, err := utils.GenerateCert()
	if err != nil {
		t.Fatalf("cert creation failed %v\n", err)
	}

	t.Logf("create cert %s and key %s \n", cert, key)
}

//---------------------------------------------------------------------------------------

func testHelpString(t *testing.T) {
	utils := CUtils{}
	test := testData{}

	helpStr := utils.GetHelp(test)

	if helpStr != "f1 : f1 help , f2 : f2 help , f3 : f3 help , f4 : f4 help" {
		t.Fatalf("invalid help string")
	}
}

//---------------------------------------------------------------------------------------

func TestUtils(t *testing.T) {
	testCertificate(t)
	testCrypto(t)
	testHelpString(t)
}

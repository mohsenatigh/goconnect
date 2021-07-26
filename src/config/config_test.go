package config

import (
	"errors"
	"fmt"
	"goconnect/utils"
	"testing"
)

type testTypeParamCommon struct {
	T string
}

type testTypeParam struct {
	testTypeParamCommon
	A string `json:"a" validate:"min=3,max=64,alphanum"`
	B string `json:"b" validate:"min=3,max=64,alphanum"`
}

type testTypeParam2 struct {
	testTypeParamCommon
	C string `json:"c" validate:"min=3,max=64,alphanum"`
	D string `json:"d" validate:"min=3,max=64,alphanum"`
}
type testType struct {
}

//---------------------------------------------------------------------------------------
func (thisPt *testType) OnCommand(segment string, in interface{}) error {

	if segment == "test" {
		param := in.(*testTypeParam)
		if param.A != "aaa" || param.B != "bbb" {
			return errors.New("invalid value")
		}
	} else if segment == "testarr" {
		//dynamic casting of array of different objects
		util := utils.Create()
		test := in.([]interface{})

		for i := range test {
			base := testTypeParamCommon{}
			if err := util.CastJsonObject(test[i], &base); err != nil {
				return err
			}

			//type is T1
			if base.T == "t1" {
				t1 := testTypeParam{}
				if err := util.CastJsonObject(test[i], &t1); err != nil {
					return err
				}
				fmt.Printf("%s\n", t1)
			} else if base.T == "t2" {
				t2 := testTypeParam2{}
				if err := util.CastJsonObject(test[i], &t2); err != nil {
					return err
				}
				fmt.Printf("%s\n", t2)
			}
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------
func testFunctionality(t *testing.T) {

	testJson := `{"test":{"t":"t1","a":"aaa","b":"bbb"},"testarr":[{"t":"t1","a":"aaa","b":"bbb"},{"t":"t2","c":"ccc","d":"ddd"}]}`
	testJsonInvalid := `{"test":{"t":"t1","a":"a","b":"b"}}`

	testActor := new(testType)

	//basic test functionality
	config := cDynamicConfigManager{}
	config.Init(utils.Create())
	config.RegisterActor("test", testTypeParam{}, testActor)
	config.RegisterActor("testarr", nil, testActor)

	//test valid json

	if err := config.LoadConfig(testJson); err != nil {
		t.Fatal(err)
	}

	//test invalid json
	if err := config.LoadConfig(testJsonInvalid); err == nil {
		t.Fatal("expect error")
	}

}

//---------------------------------------------------------------------------------------
func TestConfig(t *testing.T) {
	testFunctionality(t)
}

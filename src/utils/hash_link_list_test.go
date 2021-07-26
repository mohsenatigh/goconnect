package utils

import (
	"testing"
	"time"
)

type sTestHashStruct struct {
	a int
}

func TestHashLinkListUnit(t *testing.T) {
	testCount := 1000000
	list := cHashLinkList{}
	list.Init(256000, 100)

	for i := 0; i < testCount; i++ {
		list.Add(uint64(i), &sTestHashStruct{a: i})
	}

	if list.GetItemsCount() != uint32(testCount) {
		t.Fatalf("invalid item count \n")
	}

	compareFunc := func(inHashData interface{}, userdata interface{}) bool {
		inHashTest := inHashData.(*sTestHashStruct)
		targetHashTest := userdata.(*sTestHashStruct)
		return (inHashTest.a == targetHashTest.a)
	}

	for i := 0; i < testCount; i++ {
		item := sTestHashStruct{a: i}
		if list.Find(uint64(i), compareFunc, &item) == nil {
			t.Fatalf("look up failed\n")
		}
	}

	for i := 0; i < testCount; i++ {
		item := sTestHashStruct{a: i}
		list.Remove(uint64(i), compareFunc, &item)
	}

	if list.GetItemsCount() != 0 {
		t.Fatalf("invalid item count \n")
	}

	//check for time out
	for i := 0; i < testCount; i++ {
		list.Add(uint64(i), &sTestHashStruct{a: i})
	}

	if list.GetItemsCount() != uint32(testCount) {
		t.Fatalf("invalid item count \n")
	}

	//check time out
	et := (time.Now().Unix() + 5)
	for i := 0; i < 256000; i++ {
		list.CheckForTimeOut(nil, nil, et)
	}

	if list.GetItemsCount() != uint32(testCount) {
		t.Fatalf("time out check failed\n")
	}

	//change time
	et = (time.Now().Unix() + 110)
	for i := 0; i < 256000; i++ {
		list.CheckForTimeOut(nil, nil, et)
	}

	if list.GetItemsCount() != 0 {
		t.Fatalf("time out check failed (%d)\n", list.GetItemsCount())
	}

	t.Logf("Successfully test hash link list struct \n")
}

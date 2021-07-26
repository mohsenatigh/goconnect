package utils

import (
	"testing"
)

func TestHeapSorter(t *testing.T) {
	sorter := cHeapSorter{}

	callBack := func(key string, item interface{}) uint64 {
		return item.(uint64)
	}

	const maxItemsCount = 10
	const arrItemsCount = 64

	//test
	testArr := make([]uint64, arrItemsCount)

	sorter.Init(maxItemsCount, callBack, "")

	//test arr
	for i := range testArr {
		testArr[i] = uint64(i)
		sorter.AddItem(testArr[i])
	}

	//test items
	for i := 0; i < maxItemsCount; i++ {
		item := sorter.GetItem()
		if item.(uint64)+1 != uint64(arrItemsCount-i) {
			t.Fatalf("faild")
		}
	}

	//
	sorter.Init(maxItemsCount, callBack, "")
	testItems := []uint64{50, 10, 70, 100, 1000, 10000, 12, 1, 888, 1111, 432111}
	sorted := []uint64{432111, 10000, 1111, 1000, 888, 100, 70, 50, 12, 10}
	for _, v := range testItems {
		sorter.AddItem(v)
	}

	for i := 0; i < maxItemsCount; i++ {
		item := sorter.GetItem()
		if item.(uint64) != sorted[i] {
			t.Fatalf("faild")
		}
	}

}

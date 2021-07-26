package utils

import (
	"container/heap"
	"encoding/json"
	"goconnect/common"
)

//---------------------------------------------------------------------------------------
type cHeapSorter struct {
	callBack  common.THeapSorterCallBackFunc
	itemsList []interface{}
	sortKey   string
}

//---------------------------------------------------------------------------------------

//Len for Sort
func (thisPt *cHeapSorter) Len() int { return len(thisPt.itemsList) }

//---------------------------------------------------------------------------------------

//Swap for Sort
func (thisPt *cHeapSorter) Swap(i, j int) {
	thisPt.itemsList[i], thisPt.itemsList[j] = thisPt.itemsList[j], thisPt.itemsList[i]
}

//---------------------------------------------------------------------------------------

//Less for Sort
func (thisPt *cHeapSorter) Less(i, j int) bool {
	iVal := thisPt.callBack(thisPt.sortKey, thisPt.itemsList[i])
	jVal := thisPt.callBack(thisPt.sortKey, thisPt.itemsList[j])
	return iVal > jVal
}

//---------------------------------------------------------------------------------------

//Push for heap
func (thisPt *cHeapSorter) Push(x interface{}) {
	thisPt.itemsList = append(thisPt.itemsList, x)
}

//---------------------------------------------------------------------------------------

//Pop for heap
func (thisPt *cHeapSorter) Pop() interface{} {
	n := len(thisPt.itemsList)
	item := thisPt.itemsList[n-1]
	thisPt.itemsList = thisPt.itemsList[0 : n-1]
	return item
}

//---------------------------------------------------------------------------------------

func (thisPt *cHeapSorter) Init(itemsCount uint32, callback common.THeapSorterCallBackFunc, param string) {

	thisPt.itemsList = make([]interface{}, 0)
	thisPt.sortKey = param
	thisPt.callBack = callback

	return
}

//---------------------------------------------------------------------------------------

func (thisPt *cHeapSorter) AddItem(object interface{}) {
	heap.Push(thisPt, object)
}

//---------------------------------------------------------------------------------------

func (thisPt *cHeapSorter) ToJson() string {
	if out, err := json.MarshalIndent(thisPt.itemsList, "", ""); err == nil {
		return string(out)
	}
	return "[]"
}

//---------------------------------------------------------------------------------------

func (thisPt *cHeapSorter) GetItem() interface{} {
	object := heap.Pop(thisPt)
	return object
}

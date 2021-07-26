package utils

import (
	"goconnect/common"
	"sync"
	"sync/atomic"
	"time"
)

//---------------------------------------------------------------------------------------
type sHashLinkListNode struct {
	Key            uint64
	Data           interface{}
	LastAccessTime int64
	Next           *sHashLinkListNode
}

//---------------------------------------------------------------------------------------
type sHashLinkListSegment struct {
	Lock sync.RWMutex
	Head *sHashLinkListNode
}

//---------------------------------------------------------------------------------------

//cHashLinkList . Hash link list data structure with time out checking and distributed luck
type cHashLinkList struct {
	segments         []*sHashLinkListSegment
	itemCount        int32
	lastCheckSegment uint32
	minInActiveTime  int64
}

//---------------------------------------------------------------------------------------
func (thisPt *cHashLinkList) getTime() int64 {
	return time.Now().Unix()
}

//---------------------------------------------------------------------------------------
func (thisPt *cHashLinkList) getIndex(key uint64) uint64 {
	cnt := uint64(len(thisPt.segments))
	index := key % cnt
	return index
}

//---------------------------------------------------------------------------------------

//Iterate for IHashLinkList
func (thisPt *cHashLinkList) Iterate(callBack common.THashIterationFunc) uint32 {
	count := uint32(0)
	for i := range thisPt.segments {

		if thisPt.segments[i] == nil {
			continue
		}

		thisPt.segments[i].Lock.RLock()
		for item := thisPt.segments[i].Head; item != nil; item = item.Next {
			count++
			if callBack(item.Data) == false {
				thisPt.segments[i].Lock.RUnlock()
				return count
			}
		}
		thisPt.segments[i].Lock.RUnlock()
	}
	return count
}

//---------------------------------------------------------------------------------------

//Init for IHashLinkList
func (thisPt *cHashLinkList) Init(segmentCount int, minInActiveTime int64) bool {

	//initialize segments
	thisPt.segments = make([]*sHashLinkListSegment, segmentCount)
	thisPt.minInActiveTime = minInActiveTime
	return true
}

//---------------------------------------------------------------------------------------

//Add for IHashLinkList
func (thisPt *cHashLinkList) Add(key uint64, data interface{}) {
	index := thisPt.getIndex(key)
	segment := thisPt.segments[index]

	//check for valid segment
	if segment == nil {
		thisPt.segments[index] = &sHashLinkListSegment{}
		segment = thisPt.segments[index]
	}

	//lock segment
	segment.Lock.Lock()
	defer segment.Lock.Unlock()

	//create node
	node := &sHashLinkListNode{}
	node.Data = data
	node.Key = key
	node.LastAccessTime = thisPt.getTime()

	//append node
	node.Next = segment.Head
	segment.Head = node

	//
	atomic.AddInt32(&thisPt.itemCount, 1)
}

//---------------------------------------------------------------------------------------

//Remove for IHashLinkList
func (thisPt *cHashLinkList) Remove(key uint64, cmpFunc common.THashCompareFunc, userData interface{}) {
	index := thisPt.getIndex(key)
	segment := thisPt.segments[index]

	//check for valid segment
	if segment == nil {
		return
	}

	//lock segment
	segment.Lock.Lock()
	defer segment.Lock.Unlock()

	//remove node
	var pNode *sHashLinkListNode
	for node := segment.Head; node != nil; node = node.Next {
		if node.Key == key {
			if cmpFunc != nil && cmpFunc(node.Data, userData) == false {
				pNode = node
				continue
			}

			node.Data = nil
			if pNode != nil {
				pNode.Next = node.Next
				node.Next = nil
				node = nil
			} else {
				segment.Head = node.Next
			}
			//
			atomic.AddInt32(&thisPt.itemCount, -1)
			return
		}
		pNode = node
	}
}

//---------------------------------------------------------------------------------------

//Find for IHashLinkList
func (thisPt *cHashLinkList) Find(key uint64, cmpFunc common.THashCompareFunc, userData interface{}) interface{} {
	index := thisPt.getIndex(key)
	segment := thisPt.segments[index]

	//check for valid segment
	if segment == nil {
		return nil
	}

	//lock segment
	segment.Lock.RLock()
	defer segment.Lock.RUnlock()

	//check node
	for node := segment.Head; node != nil; node = node.Next {
		if node.Key == key {
			if cmpFunc != nil && cmpFunc(node.Data, userData) == false {
				continue
			}
			node.LastAccessTime = thisPt.getTime()
			return node.Data
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------

//CheckForTimeOut for IHashLinkList
func (thisPt *cHashLinkList) CheckForTimeOut(cmpFunc common.THashTimeOutFunc, userData interface{}, t int64) int {
	//find last segment
	index := thisPt.lastCheckSegment % uint32(len(thisPt.segments))
	atomic.AddUint32(&thisPt.lastCheckSegment, 1)

	//
	segment := thisPt.segments[index]
	if segment == nil {
		return 0
	}

	//lock segment
	segment.Lock.Lock()
	defer segment.Lock.Unlock()

	//remove node
	var pNode *sHashLinkListNode
	cnt := 0
	for node := segment.Head; node != nil; {
		delta := t - node.LastAccessTime
		if delta > thisPt.minInActiveTime {
			//check for timeout
			if cmpFunc != nil && cmpFunc(node.Data, userData, delta) == false {
				node.LastAccessTime = t
				goto next
			}
			node.Data = nil
			if pNode != nil {
				pNode.Next = node.Next
				node.Next = nil
				node = pNode
			} else {
				segment.Head = node.Next
				node = segment.Head
			}
			//
			atomic.AddInt32(&thisPt.itemCount, -1)
			cnt++
			continue
		}
	next:
		pNode = node
		node = node.Next
	}
	return cnt
}

//---------------------------------------------------------------------------------------

//Clear for IHashLinkList
func (thisPt *cHashLinkList) Clear() {
	for i := 0; i < len(thisPt.segments); i++ {
		thisPt.segments[i] = nil
	}
	thisPt.itemCount = 0
	thisPt.lastCheckSegment = 0
}

//---------------------------------------------------------------------------------------

//GetItemsCount for IHashLinkList
func (thisPt *cHashLinkList) GetItemsCount() uint32 {
	return uint32(thisPt.itemCount)
}

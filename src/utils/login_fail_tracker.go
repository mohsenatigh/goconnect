package utils

import (
	"goconnect/common"
	"hash/fnv"
	"time"
)

const trackingMaxSegment = 4096

//---------------------------------------------------------------------------------------
type sLoginFailTracketInfo struct {
	Count uint32
}

//---------------------------------------------------------------------------------------
type cLoginFailTracker struct {
	trackHash common.IHashLinkList
	utils     common.IUtils
	failCount uint32
}

//---------------------------------------------------------------------------------------
func (thisPt *cLoginFailTracker) checkForRemove(t int64) {
	for i := 0; i < trackingMaxSegment; i++ {
		thisPt.trackHash.CheckForTimeOut(nil, nil, t)
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *cLoginFailTracker) getKey(id string) uint64 {
	h := fnv.New64()
	h.Write([]byte(id))
	return h.Sum64()
}

//---------------------------------------------------------------------------------------
func (thisPt *cLoginFailTracker) findObject(id string) *sLoginFailTracketInfo {
	key := thisPt.getKey(id)
	dataIn := thisPt.trackHash.Find(key, nil, nil)
	if dataIn == nil {
		return nil
	}
	return dataIn.(*sLoginFailTracketInfo)
}

//---------------------------------------------------------------------------------------
//CanLogin for ILoginFailTracker
func (thisPt *cLoginFailTracker) CanLogin(id string) bool {
	obj := thisPt.findObject(id)
	if obj == nil {
		return true
	}

	if obj.Count >= thisPt.failCount {
		return false
	}

	return true
}

//---------------------------------------------------------------------------------------
//RegisterFail for ILoginFailTracker
func (thisPt *cLoginFailTracker) RegisterFail(id string) bool {

	//generate key
	key := thisPt.getKey(id)

	//find object
	dataIn := thisPt.findObject(id)
	if dataIn == nil {
		dataIn = new(sLoginFailTracketInfo)
		thisPt.trackHash.Add(key, dataIn)
	}
	dataIn.Count += 1
	if dataIn.Count >= thisPt.failCount {
		return false
	}
	return true
}

//---------------------------------------------------------------------------------------

func (thisPt *cLoginFailTracker) Init(util common.IUtils, maxTrackTime uint32, maxFailCount uint32) {

	thisPt.trackHash = util.CreateHashLinkList(trackingMaxSegment, uint64(maxTrackTime))
	thisPt.utils = util
	thisPt.failCount = maxFailCount

	//start clean up routin
	go func() {
		for {
			time.Sleep(30 * time.Second)
			thisPt.checkForRemove(time.Now().Unix())
		}
	}()
}

//---------------------------------------------------------------------------------------

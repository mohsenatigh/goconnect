package utils

import (
	//#include <string.h>
	"C"
	"bytes"
	"errors"
	"log"
	"unsafe"
)
import "io"

//---------------------------------------------------------------------------------------

type cBuffer struct {
	maxSize   uint32
	data      []byte
	usedSize  uint32
	readIndex uint32
}

//---------------------------------------------------------------------------------------

func (thisPt *cBuffer) Init(len uint32) {
	thisPt.maxSize = len
	thisPt.data = make([]byte, len)
}

//---------------------------------------------------------------------------------------

//IBuffer Write
func (thisPt *cBuffer) Write(data []byte) (int, error) {
	if uint32(len(data))+thisPt.usedSize > thisPt.maxSize {
		return 0, errors.New("out of memory")
	}

	copy(thisPt.data[int(thisPt.usedSize):], data)
	thisPt.usedSize += uint32(len(data))
	return len(data), nil
}

//---------------------------------------------------------------------------------------

//IBuffer Read for io.Read
func (thisPt *cBuffer) Read(buffer []byte) (int, error) {
	data := thisPt.ReadN(uint32(len(buffer)))
	if len(data) == 0 {
		return 0, io.EOF
	}
	copy(buffer, data)
	return len(data), nil
}

//---------------------------------------------------------------------------------------

//IBuffer Read
func (thisPt *cBuffer) ReadN(rlen uint32) []byte {
	delta := thisPt.usedSize - thisPt.readIndex
	if delta < rlen {
		rlen = delta
	}
	data := thisPt.data[thisPt.readIndex : thisPt.readIndex+rlen]
	thisPt.readIndex += rlen
	return data
}

//---------------------------------------------------------------------------------------

//IBuffer GetBuffer
func (thisPt *cBuffer) GetBuffer() []byte {
	return thisPt.data[thisPt.usedSize:]
}

//---------------------------------------------------------------------------------------

//IBuffer AddUsed
func (thisPt *cBuffer) AddUsed(len uint32) {
	if len+thisPt.usedSize > thisPt.maxSize {
		log.Printf("invalid write index adjust \n")
		return
	}
	thisPt.usedSize += len
}

//---------------------------------------------------------------------------------------

//IBuffer ReadUntil
func (thisPt *cBuffer) ReadUntil(token []byte) []byte {
	index := bytes.Index(thisPt.data[thisPt.readIndex:int(thisPt.usedSize)], token)
	if index == -1 {
		return nil
	}

	end := index + len(token)
	data := thisPt.data[thisPt.readIndex:end]
	thisPt.readIndex += uint32(end)
	return data
}

//---------------------------------------------------------------------------------------

//IBuffer ReadAll
func (thisPt *cBuffer) ReadAll() []byte {
	return thisPt.data[:int(thisPt.usedSize)]
}

//---------------------------------------------------------------------------------------

//IBuffer Seek
func (thisPt *cBuffer) Seek(pos uint32) {
	if pos > thisPt.usedSize {
		pos = thisPt.usedSize
	}
	thisPt.readIndex = pos
}

//---------------------------------------------------------------------------------------

//IBuffer Reset
func (thisPt *cBuffer) Reset() {
	thisPt.usedSize = 0
	thisPt.readIndex = 0
}

//---------------------------------------------------------------------------------------

//IBuffer GetUsedSize
func (thisPt *cBuffer) GetUsedSize() uint32 {
	return thisPt.usedSize
}

//---------------------------------------------------------------------------------------

//IBuffer GetTotalSize
func (thisPt *cBuffer) GetTotalSize() uint32 {
	return thisPt.maxSize
}

//---------------------------------------------------------------------------------------

//IBuffer GetUnReadSize
func (thisPt *cBuffer) GetUnReadSize() uint32 {
	return (thisPt.usedSize - thisPt.readIndex)
}

//---------------------------------------------------------------------------------------

//IBuffer String
func (thisPt *cBuffer) String() string {
	return string(thisPt.data[0:thisPt.usedSize])
}

//---------------------------------------------------------------------------------------

//IBuffer RemoveRead
func (thisPt *cBuffer) RemoveRead() {
	if thisPt.readIndex == thisPt.usedSize {
		thisPt.Reset()
		return
	}

	//performance critical operation
	index := thisPt.readIndex
	len := thisPt.usedSize
	src := unsafe.Pointer(&thisPt.data[index])
	dst := unsafe.Pointer(&thisPt.data[0])
	C.memmove(dst, src, C.size_t(len))
	thisPt.usedSize -= thisPt.readIndex
	thisPt.readIndex = 0
}

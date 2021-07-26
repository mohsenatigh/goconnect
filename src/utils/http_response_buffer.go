package utils

import (
	"errors"
	"io"
)

//---------------------------------------------------------------------------------------
type cHttpResponseBuffer struct {
	buffer    []byte
	maxSize   uint32
	readIndex uint32
}

//---------------------------------------------------------------------------------------
func (thisPt *cHttpResponseBuffer) Write(buffer []byte) (int, error) {
	if (len(buffer) + len(thisPt.buffer)) > int(thisPt.maxSize) {
		return 0, errors.New("out of memory")
	}

	thisPt.buffer = append(thisPt.buffer, buffer...)
	return len(buffer), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cHttpResponseBuffer) Close() error {
	thisPt.buffer = nil
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cHttpResponseBuffer) Read(buf []byte) (int, error) {

	if int(thisPt.readIndex) >= len(thisPt.buffer) {
		return 0, io.EOF
	}

	readLen := len(buf)
	delta := len(thisPt.buffer) - int(thisPt.readIndex)
	if readLen > delta {
		readLen = delta
	}
	copy(buf, thisPt.buffer[thisPt.readIndex:])
	thisPt.readIndex += uint32(readLen)
	return readLen, nil
}

//---------------------------------------------------------------------------------------

func (thisPt *cHttpResponseBuffer) Init(maxSize uint32) {
	thisPt.maxSize = maxSize
}

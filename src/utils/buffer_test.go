package utils

import "testing"

func TestBuffer(t *testing.T) {

	const bufferSize = 1024
	const sampeldata = "this is a test \n\n\n\n"
	const want = "\n\n\n\n"

	buffer := cBuffer{}

	buffer.Init(bufferSize)

	buffer.Write([]byte(sampeldata))

	if buffer.GetTotalSize() != bufferSize {
		t.Fatalf("invalid buffer size\n")
	}

	if buffer.GetUsedSize() != uint32(len(sampeldata)) {
		t.Fatalf("invalid buffer used size\n")
	}

	wBuffer := buffer.GetBuffer()
	if len(wBuffer) != (bufferSize - len(sampeldata)) {
		t.Fatalf("invalid buffer size for direct write\n")
	}

	data := buffer.ReadN(2048)
	if len(data) != len(sampeldata) {
		t.Fatalf("invalid buffer size for direct write\n")
	}

	//reset buffer
	buffer.Reset()
	buffer.Write([]byte(sampeldata))
	if buffer.GetUsedSize() != uint32(len(sampeldata)) {
		t.Fatalf("invalid buffer used size\n")
	}

	data = buffer.ReadUntil([]byte(want))
	if len(data) != len(sampeldata) {
		t.Fatalf("ReadUntil return invalid value\n")
	}

	data = buffer.ReadUntil([]byte("test"))
	if data != nil {
		t.Fatalf("ReadUntil return invalid value\n")
	}

	buffer.Seek(0)

	data = buffer.ReadUntil([]byte("test"))
	if len(data) != 14 {
		t.Fatalf("ReadUntil return invalid value\n")
	}

	buffer.RemoveRead()

	if int(buffer.GetUnReadSize()) != (len(sampeldata) - 14) {
		t.Fatalf("ReadUntil return invalid value\n")
	}

}

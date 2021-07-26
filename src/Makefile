FLAG := -ldflags "-s -w"

$(shell rm ../goconnect.bin)

release: FLAG = -ldflags "-s -w"
release: all

debug: FLAG = 
debug: all

all: goconnect.bin

goconnect.bin:
	go build $(FLAG) -o ../goconnect.bin goconnect.go

test:
	go test src/goconnect/

clean:
	rm -f goconnect.bin


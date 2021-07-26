package utils

import (
	"fmt"
	"log"
	"net"
	"testing"
	"time"
)

func TestIPTrie(t *testing.T) {

	Trie := cIPTrie{}
	Trie.Init(4)
	//add simple node
	Trie.AddString("192.168.1.0/24", 1)
	if Trie.SearchString("192.168.1.1") == nil {
		log.Fatalln("failed ")
	}

	if Trie.SearchExactString("192.168.1.0/24") == nil {
		log.Fatalln("failed ")
	}

	if Trie.SearchExactString("192.168.1.0/32") != nil {
		log.Fatalln("failed ")
	}

	if Trie.SearchString("192.168.1.1") == nil {
		log.Fatalln("failed ")
	}

	if Trie.SearchString("192.168.1.0") == nil {
		log.Fatalln("failed ")
	}

	if Trie.SearchString("192.168.1.255") == nil {
		log.Fatalln("failed ")
	}

	if Trie.SearchString("192.168.2.1") != nil {
		log.Fatalln("failed ")
	}

	//simple search
	Trie.AddString("192.168.0.0/16", 2)
	if Trie.SearchString("192.168.2.1") == nil {
		log.Fatalln("failed ")
	}

	sr := Trie.SearchString("192.168.1.10")
	if sr.(int) != 1 {
		log.Fatalln("failed ")
	}

	sr = Trie.SearchString("192.168.3.10")
	if sr.(int) != 2 {
		log.Fatalln("failed ")
	}

	Trie.RemoveString("192.168.0.0/16")
	if Trie.SearchString("192.168.3.10") != nil {
		log.Fatalln("failed ")
	}

	//load test
	ip := net.ParseIP("192.168.1.255")
	start := time.Now()
	for i := 0; i < 10000000; i++ {
		if Trie.Search(ip) == nil {
			t.Fatalf("IP Trie search failed \n")
		}
	}
	end := time.Since(start)
	t.Logf("search Trie in %d \n", end/1000000)

	//test iteration
	Trie.Flush()

	for i := 0; i < 200; i++ {
		Trie.AddString(fmt.Sprintf("192.168.0.%d/32", i), i)
	}

	if Trie.Iterate(nil) != 200 {
		t.Fatalf("Iteration failed\n")
	}

}

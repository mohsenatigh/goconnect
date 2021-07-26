package auth

import (
	"fmt"
	"testing"
)

type base struct {
}

type child struct {
	base
}

func (thisPt *base) call() {
	fmt.Printf("call from base\n")
}

func (thisPt *base) call2() {
	fmt.Printf("call2 from base\n")
}

func (thisPt *child) call() {
	fmt.Printf("call from child\n")
	thisPt.base.call()
}

func TestDummyAuth(t *testing.T) {
	c := child{}
	c.call()
	c.call2()
}

package utils

import (
	"goconnect/common"
	"net"
)

//
type sIPTriNode struct {
	nodes [2]*sIPTriNode
	Value interface{}
}

//
type cIPTrie struct {
	root      sIPTriNode
	ipVersion int
}

//---------------------------------------------------------------------------------------

//
func (thisPt *cIPTrie) getIPBit(ip net.IP, bit uint32) int {
	index := (bit >> 3)
	bitIndex := bit % 8
	mask := (byte(0x80) >> bitIndex)

	if thisPt.ipVersion == 4 && len(ip) > 4 {
		index += 12
	}

	if (ip[index] & mask) > 0 {
		return 1
	}
	return 0
}

//---------------------------------------------------------------------------------------

//
func (thisPt *cIPTrie) findNode(ip net.IP, layer uint32) *sIPTriNode {
	var i uint32
	var bestVal *sIPTriNode
	mask := uint32(32)
	if thisPt.ipVersion == 6 {
		mask = 128
	}

	activeNode := &thisPt.root
	for i = 0; i < mask; i++ {
		bit := thisPt.getIPBit(ip, i)

		if activeNode.nodes[bit] == nil {
			//check for layer. normaly used for duplicate detection
			if layer != 0 {
				return nil
			}
			return bestVal
		}

		activeNode = activeNode.nodes[bit]
		if activeNode.Value != nil {

			//check for layer normaly used for duplicate detection
			if layer != 0 && layer == i {
				return activeNode
			}

			bestVal = activeNode
		}
	}
	return bestVal
}

//---------------------------------------------------------------------------------------

func (thisPt *cIPTrie) callNodeForIteration(node *sIPTriNode, callback common.TIPTrieCallBackFunc) uint32 {
	itemsCount := uint32(0)

	checkNode := func(node *sIPTriNode) {
		if node != nil {
			if node.Value != nil {
				if callback != nil {
					callback(node.Value)
				}
				itemsCount++
			}
			itemsCount += thisPt.callNodeForIteration(node, callback)
		}
	}

	checkNode(node.nodes[0])
	checkNode(node.nodes[1])
	return itemsCount
}

//---------------------------------------------------------------------------------------

//AddString for IIPTrie
func (thisPt *cIPTrie) Iterate(callback common.TIPTrieCallBackFunc) uint32 {
	return thisPt.callNodeForIteration(&thisPt.root, callback)
}

//---------------------------------------------------------------------------------------

//AddString for IIPTrie
func (thisPt *cIPTrie) AddString(ipMask string, value interface{}) error {
	_, inet, err := net.ParseCIDR(ipMask)
	if err != nil {
		return err
	}

	bits, _ := inet.Mask.Size()
	thisPt.Add(inet.IP, uint32(bits), value)
	return nil
}

//---------------------------------------------------------------------------------------

//Add for IIPTrie
func (thisPt *cIPTrie) Add(ip net.IP, mask uint32, value interface{}) {
	var i uint32
	activeNode := &thisPt.root
	for i = 0; i < mask; i++ {
		bit := thisPt.getIPBit(ip, i)
		if activeNode.nodes[bit] == nil {
			activeNode.nodes[bit] = &sIPTriNode{}
		}
		activeNode = activeNode.nodes[bit]
	}
	activeNode.Value = value
}

//---------------------------------------------------------------------------------------

//SearchString for IIPTrie
func (thisPt *cIPTrie) SearchString(ip string) interface{} {
	ipVal := net.ParseIP(ip)
	return thisPt.Search(ipVal)
}

//---------------------------------------------------------------------------------------

//Search for IIPTrie
func (thisPt *cIPTrie) Search(ip net.IP) interface{} {
	node := thisPt.findNode(ip, 0)
	if node == nil {
		return nil
	}
	return node.Value
}

//---------------------------------------------------------------------------------------

//Search for IIPTrie
func (thisPt *cIPTrie) SearchExact(ip net.IP, mask uint32) interface{} {
	node := thisPt.findNode(ip, mask-1)
	if node == nil {
		return nil
	}
	return node.Value
}

//---------------------------------------------------------------------------------------

//SearchExactString for IIPTrie
func (thisPt *cIPTrie) SearchExactString(ipMask string) interface{} {
	_, inet, err := net.ParseCIDR(ipMask)
	if err != nil {
		return err
	}

	bits, _ := inet.Mask.Size()
	return thisPt.SearchExact(inet.IP, uint32(bits))
}

//---------------------------------------------------------------------------------------

//Remove for IIPTrie
func (thisPt *cIPTrie) Remove(ip net.IP, mask uint32) interface{} {
	node := thisPt.findNode(ip, 0)
	if node == nil {
		return nil
	}
	value := node.Value
	node.Value = nil
	return value
}

//---------------------------------------------------------------------------------------

//RemoveString for IIPTrie
func (thisPt *cIPTrie) RemoveString(ipMask string) interface{} {
	_, inet, err := net.ParseCIDR(ipMask)
	if err != nil {
		return err
	}
	bits, _ := inet.Mask.Size()
	return thisPt.Remove(inet.IP, uint32(bits))
}

//---------------------------------------------------------------------------------------

//Flush for IIPTrie
func (thisPt *cIPTrie) Flush() {
	for i := range thisPt.root.nodes {
		thisPt.root.nodes[i] = nil
	}
}

//---------------------------------------------------------------------------------------

//Init for IIPTrie
func (thisPt *cIPTrie) Init(ipVersion int) {
	thisPt.ipVersion = ipVersion
}

package main

import (
	"net/netip"
	"sync"
)

type RadixNode struct {
	Prefix  *netip.Prefix
	Payload string
	Left    *RadixNode
	Right   *RadixNode
}

type CorporateNetworkIndex struct {
	sync.RWMutex
	RootNode *RadixNode
}

var networkClassificationIndex = &CorporateNetworkIndex{}

func (cni *CorporateNetworkIndex) Insert(prefix netip.Prefix, payload string) {
	cni.Lock()
	defer cni.Unlock()
	cni.RootNode = insertNode(cni.RootNode, prefix, payload, 0)
}

func insertNode(node *RadixNode, prefix netip.Prefix, payload string, bitIndex int) *RadixNode {
	if node == nil {
		node = &RadixNode{}
	}
	if bitIndex == prefix.Bits() {
		p := prefix
		node.Prefix = &p
		node.Payload = payload
		return node
	}
	bit := getBit(prefix.Addr(), bitIndex)
	if bit == 0 {
		node.Left = insertNode(node.Left, prefix, payload, bitIndex+1)
	} else {
		node.Right = insertNode(node.Right, prefix, payload, bitIndex+1)
	}
	return node
}

func (cni *CorporateNetworkIndex) MatchLongestPrefix(addr netip.Addr) (string, bool) {
	cni.RLock()
	defer cni.RUnlock()
	var bestPayload string
	var found bool
	curr := cni.RootNode
	for bitIndex := 0; curr != nil; bitIndex++ {
		if curr.Prefix != nil && curr.Prefix.Contains(addr) {
			bestPayload = curr.Payload
			found = true
		}
		if bitIndex >= addr.BitLen() {
			break
		}
		bit := getBit(addr, bitIndex)
		if bit == 0 {
			curr = curr.Left
		} else {
			curr = curr.Right
		}
	}
	return bestPayload, found
}

func getBit(addr netip.Addr, bitIndex int) int {
	bytes := addr.AsSlice()
	byteIdx := bitIndex / 8
	bitIdx := 7 - (bitIndex % 8)
	if byteIdx >= len(bytes) {
		return 0
	}
	return int((bytes[byteIdx] >> bitIdx) & 1)
}

func initNetworkClassificationIndex() {
	cdns := map[string][]string{
		"cloudflare": {
			"104.16.0.0/12", "172.64.0.0/13", "2606:4700::/32",
		},
		"fastly": {
			"151.101.0.0/16", "2a04:4e42::/32",
		},
		"cloudfront": {
			"13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "54.230.0.0/16",
		},
		"akamai": {
			"23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13", "2a02:26f0::/32",
		},
	}
	for payload, cidrs := range cdns {
		for _, cidr := range cidrs {
			if prefix, err := netip.ParsePrefix(cidr); err == nil {
				networkClassificationIndex.Insert(prefix, payload)
			}
		}
	}
}

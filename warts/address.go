/*
 Copyright (c) 2015, Northeastern University
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of the Northeastern University nor the
       names of its contributors may be used to endorse or promote products
       derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL Northeastern University BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package warts

import (
	"io"
	"sync"

	"github.com/NEU-SNS/revtrvp/util"
)

// Address represents an address
type Address struct {
	Type    uint8
	Address uint64
}

func (a Address) String() string {
	switch a.Type {
	case 0x01:
		ip, err := util.Int32ToIPString(uint32(a.Address))
		if err != nil {
			return ""
		}
		return ip
	case 0x02, 0x03, 0x04:
		return ""
	}
	return ""
}

// AddressRefs tracks the addresses in a warts file
type AddressRefs struct {
	mu    sync.Mutex
	id    uint32
	addrs map[uint32]Address
}

// Add adds an address to the AddressRefs
func (ar *AddressRefs) Add(addr Address) {
	ar.mu.Lock()
	id := ar.id
	ar.id++
	ar.addrs[id] = addr
	ar.mu.Unlock()
}

// Get gets an address by id from addressrefs
func (ar *AddressRefs) Get(id uint32) Address {
	return ar.addrs[id]
}

// NewAddressRefs creates a new AddressRefs structure
func NewAddressRefs() *AddressRefs {
	return &AddressRefs{
		addrs: make(map[uint32]Address),
	}
}

func readReferencedAddress(f io.Reader, addrs *AddressRefs) (Address, error) {
	addr, err := readUint32(f)
	if err != nil {
		return Address{}, err
	}
	return addrs.Get(addr), nil
}

func readAddress(f io.Reader, addrs *AddressRefs) (Address, error) {
	a := Address{}
	length, err := readUint8(f)
	if err != nil {
		return a, err
	}
	if length == 0 {
		id, err := readUint32(f)
		if err != nil {
			return a, err
		}
		return addrs.Get(id), nil
	}
	t, err := readUint8(f)
	if err != nil {
		return a, err
	}
	res, err := readBytes(f, int(length))
	if err != nil {
		return a, err
	}
	addr := sliceToUint64(res)
	a.Type = t
	a.Address = addr
	addrs.Add(a)
	return a, nil

}

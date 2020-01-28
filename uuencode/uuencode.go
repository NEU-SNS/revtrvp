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

package uuencode

import (
	"bytes"
	"io"
)

// UUEncode encodes the bytes in p
func UUEncode(p []byte) ([]byte, error) {
	var results []byte
	buf := bytes.NewBuffer(p)
	var line [45]byte
	for {
		n, err := buf.Read(line[:])
		if err == io.EOF {
			results = append(results, byte('`'), byte('\n'))
			return results, nil
		}
		if err != nil {
			return nil, err
		}
		encl, err := uuencodeLine(line[:n])
		if err != nil {
			return nil, err
		}
		results = append(results, encl...)
		results = append(results, byte('\n'))
	}
}

func uuencodeLine(e []byte) ([]byte, error) {
	length := len(e)
	total := (length / 3) * 4
	// if there are remaining bytes add them on
	remain := length % 3
	uselen := length
	if remain > 0 {
		uselen += (3 - remain)
		total += 4
	}
	// make a local copy, we might need to pad so we dont want to override
	// anything in the array backing the slice
	local := make([]byte, length)
	copy(local, e)
	for i := 0; i < remain; i++ {
		// Bad null bytes if not multiple of 3
		local = append(local, 0)
	}
	//For the length byte
	total++
	ret := make([]byte, total)
	ret[0] = enc(byte(length))
	for i := 0; i < uselen/3; i++ {
		offs := i * 3
		enc, err := uuencodeBytes(local[offs : offs+3])
		if err != nil {
			return nil, err
		}
		newoffs := i*4 + 1
		copy(ret[newoffs:newoffs+4], enc)
	}
	return ret, nil
}

func enc(b byte) byte {
	if b == 0 {
		return byte('`')
	}
	return b + byte(' ')
}

func uuencodeBytes(by []byte) ([]byte, error) {
	bytes := make([]byte, 4)
	bytes[0] = enc((by[0] >> 2))
	bytes[1] = enc(((by[0] & 0x3 << 4) | by[1]>>4))
	bytes[2] = enc((((by[1] & 0x0F) << 2) | (by[2] >> 6)))
	bytes[3] = enc((by[2] & 0x3F))
	return bytes, nil
}

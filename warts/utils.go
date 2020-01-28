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
	"bytes"
	"fmt"
	"io"
	"syscall"
)

func isset(val, pos uint8) bool {
	shift := pos - 1
	return val&(1<<shift) != 0
}

func getUint32(in []byte) uint32 {
	var ret uint32
	ret |= uint32(in[0]) << 24
	ret |= uint32(in[1]) << 16
	ret |= uint32(in[2]) << 8
	ret |= uint32(in[3])
	return ret
}

func readUint32(f io.Reader) (uint32, error) {
	in := make([]byte, 4)
	n, err := f.Read(in)
	if err != nil {
		return 0, fmt.Errorf("Failed to read uint16 flag: %v", err)
	}
	if n != 4 {
		return 0, fmt.Errorf("Bad Read readUint16")
	}
	return getUint32(in), nil
}

func getUint8(in []byte) uint8 {
	return uint8(in[0])
}

func readUint8(f io.Reader) (uint8, error) {
	in := make([]byte, 1)
	n, err := f.Read(in)
	if err != nil {
		return 0, fmt.Errorf("Failed to read uint16 flag: %v", err)
	}
	if n != 1 {
		return 0, fmt.Errorf("Bad Read readUint16")
	}
	return getUint8(in), nil
}

func getUint16(in []byte) uint16 {
	var ret uint16
	ret |= uint16(in[0]) << 8
	ret |= uint16(in[1])
	return ret
}

func readUint16(f io.Reader) (uint16, error) {
	in := make([]byte, 2)
	n, err := f.Read(in)
	if err != nil {
		return 0, fmt.Errorf("Failed to read uint16 flag: %v", err)
	}
	if n != 2 {
		return 0, fmt.Errorf("Bad Read readUint16")
	}
	return getUint16(in), nil
}

func readTimeVal(f io.Reader) (syscall.Timeval, error) {
	ret := syscall.Timeval{}
	sec, err := readUint32(f)
	if err != nil {
		return ret, err
	}
	setSecond(&ret, sec)
	usec, err := readUint32(f)
	if err != nil {
		return ret, err
	}
	setUSecond(&ret, usec)
	return ret, nil
}

func getString(f io.Reader) (string, error) {
	var buf bytes.Buffer
	temp := make([]byte, 1)
	for {
		n, err := f.Read(temp)
		if err != nil {
			return "", err
		}
		if n != 1 {
			return "", fmt.Errorf("getString bad read length: %d", n)
		}
		if temp[0] == 0x00 {
			return buf.String(), nil
		}
		err = buf.WriteByte(temp[0])
		if err != nil {
			return "", err
		}
	}
}

func readOne(f io.Reader) (uint8, error) {
	read := make([]byte, 1)
	n, err := f.Read(read)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, fmt.Errorf("readOne failed")
	}
	return uint8(read[0]), nil
}

func readBytes(f io.Reader, n int) ([]byte, error) {
	read := make([]byte, n)
	c, err := f.Read(read)
	if err != nil {
		return nil, err
	}
	if c != n {
		return nil, fmt.Errorf("Failed to read, readBytes")
	}
	return read, nil
}

func sliceToUint64(in []byte) uint64 {
	var ret uint64
	if len(in) > 8 {
		return ret
	}
	for i := 0; i < len(in); i++ {
		ret |= uint64(in[i]) << uint(8*(len(in)-i-1))
	}
	return ret
}

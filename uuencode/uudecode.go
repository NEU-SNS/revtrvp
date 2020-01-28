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
	"errors"
)

var (
	// ErrorUUDecDone is the error for indicating the UUDecoding is done
	errorUUDecDone = errors.New("Decoding Done")
	// ErrorInvalidByte is the error for an invalid byte in a UUDecoding
	ErrorInvalidByte = errors.New("InvalidByte")
)

// UUDecodingWriter decodes uuencoded bytes that are written to it
type UUDecodingWriter struct {
	b bytes.Buffer
}

// Write uudecodes the bytes in p
func (w *UUDecodingWriter) Write(p []byte) (n int, err error) {
	res, err := UUDecode(p)
	if err != nil {
		return 0, err
	}
	return w.b.Write(res)
}

// Bytes gets the result bytes from a UUDecodingWriter
func (w *UUDecodingWriter) Bytes() []byte {
	return w.b.Bytes()
}

// UUDecode decodes the uuencoded bytes in e
func UUDecode(e []byte) ([]byte, error) {

	sep := []byte{'\n'}
	result := make([]byte, 0, len(e))
	lines := bytes.Split(e, sep)
	for _, line := range lines {
		if len(line) == 0 || line[0] > 96 || line[0] < 32 {
			break
		}
		ue, err := uudecodeLine(line)
		if err != nil && err != errorUUDecDone {
			return nil, err
		}
		result = append(result, ue...)
	}
	return result, nil
}

func uudecodeLine(e []byte) ([]byte, error) {
	if len(e) == 1 && e[0] == '`' {
		return nil, errorUUDecDone
	}
	lenB := uint(e[0] - 32)
	e = e[1:]
	result := make([]byte, 0, lenB)
	for i := 0; i < len(e); i += 4 {
		s, err := uudecodeBytes(e[i : i+4])
		if err != nil {
			return nil, err
		}
		result = append(result, s...)
	}
	return result[:lenB], nil
}

func uudecodeBytes(by []byte) ([]byte, error) {
	bytes := make([]byte, 3)
	if (by[0] > 96 || by[0] < 32) ||
		(by[1] > 96 || by[1] < 32) ||
		(by[2] > 96 || by[2] < 32) ||
		(by[3] > 96 || by[3] < 32) {
		return nil, ErrorInvalidByte
	}
	bytes[0] = (((by[0] - 32) & 0x3F) << 2 & 0xFC) | (((by[1] - 32) & 0x3F) >> 4 & 0x3)
	bytes[1] = (((by[1] - 32) & 0x3F) << 4 & 0xF0) | (((by[2] - 32) & 0x3F) >> 2 & 0xF)
	bytes[2] = (((by[2] - 32) & 0x3F) << 6 & 0xC0) | ((by[3] - 32) & 0x3F)

	return bytes, nil
}

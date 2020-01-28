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

// Package scamper is a library to work with scamper control sockets
package scamper_test

import (
	"bufio"
	"log"
	"net"
	"testing"

	"github.com/NEU-SNS/revtrvp/datamodel"
	"github.com/NEU-SNS/revtrvp/scamper"
)

type dumpListener struct {
	Lis net.Listener
}

func newDumpListener() (*dumpListener, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			con, err := lis.Accept()
			if err != nil {
				panic(err)
			}
			go func(c net.Conn) {
				buf := make([]byte, 1024*1024*1024)
				for {
					read := bufio.NewReader(c)
					_, err := read.Read(buf)
					if err != nil {
						log.Println(err)
						return
					}
				}
			}(con)
		}
	}()
	return &dumpListener{Lis: lis}, nil
}

func BenchmarkSocket(b *testing.B) {
	dl, err := newDumpListener()
	if err != nil {
		b.Fatal(err)
	}
	con, err := net.Dial(dl.Lis.Addr().Network(), dl.Lis.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	sock, err := scamper.NewSocket("benchmarksocket", con)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	dm := &datamodel.PingMeasurement{
		Src:   81341342,
		Dst:   1341341,
		RR:    true,
		Count: "1",
	}
	for i := 0; i < b.N; i++ {
		_, _, err := sock.DoMeasurement(dm)
		if err != nil {
			b.Fatal(err)
		}
	}
}

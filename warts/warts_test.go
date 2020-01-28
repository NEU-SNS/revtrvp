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

package warts_test

import (
	"io/ioutil"
	"testing"

	"github.com/NEU-SNS/revtr-vp/datamodel"
	"github.com/NEU-SNS/revtr-vp/warts"
)

func TestParsePing(t *testing.T) {

	content, err := ioutil.ReadFile("../doc/test_warts.warts")
	if err != nil {
		t.Fatal("ParsePing could not read file")
	}
	pingFilter := make([]warts.WartsT, 1)
	pingFilter[0] = warts.PingT
	_, err = warts.Parse(content, pingFilter)
	if err != nil {
		t.Fatalf("ParsePing failed: %v", err)
	}
}

func TestParsePingTSPreSpec(t *testing.T) {
	content, err := ioutil.ReadFile("../doc/test_tsprespec2.warts")
	if err != nil {
		t.Fatal("ParsePing could not read file")
	}
	pingFilter := make([]warts.WartsT, 1)
	pingFilter[0] = warts.PingT
	p, err := warts.Parse(content, pingFilter)
	t.Log(p[0].(warts.Ping).PingReplies[0].V4TS)
	if !p[0].(warts.Ping).IsTsAndAddr() {
		t.Fatal("TSPreSpec is not TsAndAddr")
	}
	if err != nil {
		t.Fatalf("ParsePing failed: %v", err)
	}
}

func TestParsePingTSOnly(t *testing.T) {
	content, err := ioutil.ReadFile("../doc/test_tsonly.warts")
	if err != nil {
		t.Fatal("ParsePing could not read file")
	}
	pingFilter := make([]warts.WartsT, 1)
	pingFilter[0] = warts.PingT
	p, err := warts.Parse(content, pingFilter)
	t.Log(p[0].(warts.Ping).PingReplies[0].V4TS)
	if p[0].(warts.Ping).IsTsAndAddr() {
		t.Fatal("TSPreSpec is TsAndAddr")
	}
	t.Log(p[0].(warts.Ping).Flags.PF.Strings())
	if !p[0].(warts.Ping).IsTsOnly() {
		t.Fatal("TSPreSpec is not TsOnly")
	}
	if err != nil {
		t.Fatalf("ParsePing failed: %v", err)
	}
}

func TestParsePingRR(t *testing.T) {
	content, err := ioutil.ReadFile("../doc/rr_test.warts")
	if err != nil {
		t.Fatal("ParsePing could not read file")
	}
	pingFilter := make([]warts.WartsT, 1)
	pingFilter[0] = warts.PingT
	_, err = warts.Parse(content, pingFilter)
	if err != nil {
		t.Fatalf("ParsePing failed: %v", err)
	}
}

func TestTrace(t *testing.T) {
	content, err := ioutil.ReadFile("../doc/trace_test.warts")
	if err != nil {
		t.Fatal("TestTrace could not read file")
	}
	traceFilter := make([]warts.WartsT, 1)
	traceFilter[0] = warts.TracerouteT
	res, err := warts.Parse(content, traceFilter)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	for _, item := range res {
		switch item.(type) {
		case warts.Traceroute:
		}
	}
}
func TestTraceFirstHop(t *testing.T) {
	content, err := ioutil.ReadFile("../doc/test_firsthop_trace.warts")
	if err != nil {
		t.Fatal("TestTraceFirstHop could not read file")
	}
	traceFilter := make([]warts.WartsT, 1)
	traceFilter[0] = warts.TracerouteT
	res, err := warts.Parse(content, traceFilter)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	for _, item := range res {
		switch item.(type) {
		case warts.Traceroute:
		}
	}
}

var result []interface{}

func BenchmarkParse(b *testing.B) {
	content, err := ioutil.ReadFile("../doc/rr_test.warts")
	if err != nil {
		b.Fatal("ParsePing could not read file")
	}
	b.ResetTimer()
	var res []interface{}
	for i := 0; i < b.N; i++ {
		pingFilter := make([]warts.WartsT, 1)
		pingFilter[0] = warts.PingT
		res, _ = warts.Parse(content, pingFilter)
		for _, item := range res {
			switch i := item.(type) {
			case warts.Ping:
				datamodel.ConvertPing(i)
			}
		}
	}
	result = res
}

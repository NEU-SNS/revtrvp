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

package scamper_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/NEU-SNS/revtrvp/datamodel"
	"github.com/NEU-SNS/revtrvp/scamper"
	"github.com/NEU-SNS/revtrvp/scamper/internal"
	"github.com/NEU-SNS/revtrvp/util"
)

var sockPath = "/tmp/192.168.1.2:5000"
var testIP = "192.168.1.2"
var testPort = "5000"

func TestSocketStop(t *testing.T) {
	defer util.LeakCheck(t)()
	s := internal.NewServer(sockPath, nil)
	s.Start()
	defer s.Stop()
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to Dial socket: %v", err)
	}
	sock, err := scamper.NewSocket(sockPath, c)
	if err != nil {
		t.Fatalf("Failed to create a socket: %v", err)
	}
	sock.Stop()
}

func TestSocketIP_Port(t *testing.T) {
	defer util.LeakCheck(t)()
	s := internal.NewServer(sockPath, nil)
	s.Start()
	defer s.Stop()
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to Dial socket: %v", err)
	}
	sock, err := scamper.NewSocket(sockPath, c)
	if err != nil {
		t.Fatalf("Failed to create a socket: %v", err)
	}
	if sock.IP() != "192.168.1.2" {
		t.Fatalf("Failed getting socket IP expected[192.168.1.2] got[%s]", sock.IP())
	}
	if sock.Port() != "5000" {
		t.Fatalf("Failed getting socket Port expected[5000] got [%s]", sock.Port())
	}
	sock.Stop()
}

func TestDisconnectSocket(t *testing.T) {
	defer util.LeakCheck(t)()
	s := internal.NewServer(sockPath, nil)
	s.Start()
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to Dial socket: %v", err)
	}
	sock, err := scamper.NewSocket(sockPath, c)
	if err != nil {
		t.Fatalf("Failed to create a socket: %v", err)
	}
	s.Stop()
	<-time.After(time.Second * 1)
	_, _, err = sock.DoMeasurement(&datamodel.PingMeasurement{
		Src: 1111111111,
		Dst: 2222222222,
	})
	if err != scamper.ErrSocketClosed {
		t.Fatalf("TestDisconnectSocket, Expected[%v], Got[%v]", scamper.ErrSocketClosed, err)
	}
}

func TestSendOnClosedSocket(t *testing.T) {
	defer util.LeakCheck(t)()
	s := internal.NewServer(sockPath, nil)
	s.Start()
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to Dial socket: %v", err)
	}
	defer s.Stop()
	defer c.Close()
	sock, err := scamper.NewSocket(sockPath, c)
	if err != nil {
		t.Fatalf("Failed to create a socket: %v", err)
	}
	sock.Stop()
	_, _, err = sock.DoMeasurement(&datamodel.PingMeasurement{
		Src: 1111111111,
		Dst: 2222222222,
	})
	if err != scamper.ErrSocketClosed {
		t.Fatalf("TestDisconnectSocket, Expected[%v], Got[%v]", scamper.ErrSocketClosed, err)
	}
}

func TestCmd(t *testing.T) {
	pm := &datamodel.PingMeasurement{
		Src: 1111111111,
		Dst: 2222222222,
	}
	tm := &datamodel.TracerouteMeasurement{
		Src: 1111111111,
		Dst: 2222222222,
	}
	c := scamper.Cmd{ID: 5, Arg: pm}
	res := &bytes.Buffer{}
	c.IssueCommand(res)
	t.Log(res.String())
	res.Reset()
	c.Arg = tm
	c.IssueCommand(res)
	t.Log(res.String())
}

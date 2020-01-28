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
 ANY EXPRESS OR IMPROCLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPROCLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL Northeastern University BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPROCLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package mproc_test

import (
	"os"
	"testing"

	"github.com/NEU-SNS/revtrvp/mproc"
	"github.com/NEU-SNS/revtrvp/mproc/proc"
)

func TestManageProcess(t *testing.T) {

	pm := mproc.New()
	p := proc.New("/bin/true", nil)
	if p == nil {
		t.Fatal("Could not create process")
	}
	_, err := pm.ManageProcess(p, false, 0)
	if err != nil {
		t.Fatal("Process was not started")
	}
}

func TestKeepAlive(t *testing.T) {
	pm := mproc.New()
	p := proc.New("/bin/sleep", nil, "10")
	if p == nil {
		t.Fatal("Could not create process")
	}
	_, err := pm.ManageProcess(p, true, 2)
	if err != nil {
		t.Fatal("Process was not started")
	}
	if err != nil {
		t.Fatalf("EndKeepAlive failed: %v", err)
	}
}

func TestEndKeepAlive(t *testing.T) {
	pm := mproc.New()
	p := proc.New("/bin/sleep", nil, "1")
	if p == nil {
		t.Fatal("Could not create process")
	}
	id, err := pm.ManageProcess(p, true, 1000)
	if err != nil {
		t.Fatal("Process was not started")
	}
	err = pm.EndKeepAlive(id)
	if err != nil {
		t.Fatalf("EndKeepAlive failed: %v", err)
	}

}

func TestGetProc(t *testing.T) {

	pm := mproc.New()
	p := proc.New("/bin/true", nil)
	id, err := pm.ManageProcess(p, false, 0)
	if err != nil {
		t.Fatal("TestGetProc failed to manage proc")
	}
	np := pm.GetProc(id)
	if np == nil {
		t.Fatalf("Get proc failed")
	}
}

func TestWait(t *testing.T) {
	pm := mproc.New()
	p := proc.New("/bin/true", nil)
	id, err := pm.ManageProcess(p, false, 0)
	if err != nil {
		t.Fatal("TestWait failed to manage process")
	}
	done := <-pm.WaitProc(id)
	if done != nil {
		t.Fatalf("Wait failed: %v", done)
	}
	ws := pm.GetProc(id).GetWaitStatus()
	if ws == nil {
		t.Fatalf("Wait failed to set ProcState: %v", ws)
	}
}

func TestKill(t *testing.T) {
	pm := mproc.New()
	p := proc.New("/bin/sleep", nil, "20")
	if p == nil {
		t.Fatal("Could not create process")
	}
	id, err := pm.ManageProcess(p, false, 0)
	if err != nil {
		t.Fatal("TestKill failed to manage process")
	}
	pm.KillProc(id)
	done := <-pm.WaitProc(id)
	if done != nil {
		t.Fatal("Failed to wait in Testkill")
	}
	ps := p.GetWaitStatus()
	if ps.String() != "signal: killed" {
		t.Fatalf("Proc Was not killed: %v", ps)
	}
}

func TestStartFatal(t *testing.T) {
	pm := mproc.New()
	p := proc.New("true", nil)
	_, err := pm.ManageProcess(p, false, 0)

	if err == nil {
		t.Fatal("Failed Proc didn't return error")
	}
}

func TestKillNoProc(t *testing.T) {
	pm := mproc.New()
	err := pm.KillProc(10000)
	if err == nil {
		t.Fatal("Kill, Err not returned for invalid pid")
	}

}

func TestSignal(t *testing.T) {
	pm := mproc.New()
	p := proc.New("/bin/sleep", nil, "20")
	if p == nil {
		t.Fatal("Could not create process")
	}
	id, err := pm.ManageProcess(p, false, 0)
	if err != nil {
		t.Fatal("TestSignal failed to manage process")
	}
	e := pm.SignalProc(id, os.Kill)
	if e != nil {
		t.Fatal("TestSignal failed to signal proc")
	}
	done := <-pm.WaitProc(id)
	if done != nil {
		t.Fatal("Failed to wait in TestSignal")
	}
	ps := p.GetWaitStatus()
	if ps.String() != "signal: killed" {
		t.Fatalf("Proc Was not signaled: %v", ps)
	}
}

func TestSignalBadPid(t *testing.T) {
	pm := mproc.New()
	err := pm.SignalProc(100000, os.Kill)
	if err == nil {
		t.Fatal("Failed to return error on invalid Pid")
	}
}

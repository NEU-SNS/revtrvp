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
package proc

import (
	"os"
	"testing"
)

func TestWait(t *testing.T) {
	proc := &Process{prog: "/bin/true"}
	if proc == nil {
		t.Error("Could not create process")
	}
	_, err := proc.Start()
	if err != nil {
		t.Error("TestWait Failed to start process.")

	}
	done := <-proc.Wait()
	if done != nil {
		t.Error("TestWaitWait failed: ", done)
	}
	waitStatus := proc.GetWaitStatus()

	if waitStatus == nil {
		t.Error("TestWait Wait failed to set ProcState: ", waitStatus)
	}
}

func TestKill(t *testing.T) {
	proc := &Process{prog: "/bin/sleep", argv: []string{"20"}}
	if proc == nil {
		t.Error("Could not create process")
	}
	_, err := proc.Start()
	if err != nil {
		t.Error("Failed to start proc")
	}
	if e := proc.Kill(); e != nil {
		t.Error("TestKill Kill failed: ", e)
	}

	done := <-proc.Wait()
	if done != nil {
		t.Error("Failed to wait in Testkill")
	}
	if proc.GetWaitStatus().String() != "signal: killed" {
		t.Error("Proc Was not killed: ", proc.GetWaitStatus())
	}
}

func TestStartError(t *testing.T) {
	proc := &Process{prog: "true"}
	_, err := proc.Start()

	if err == nil {
		t.Error("Failed Proc didn't return error")
	}
}

func TestSignal(t *testing.T) {
	proc := &Process{prog: "/bin/sleep", argv: []string{"20"}}
	if proc == nil {
		t.Error("Could not create process")
	}
	_, err := proc.Start()
	if err != nil {
		t.Error("TestSignal Failed to start process")
	}

	if e := proc.Signal(os.Kill); e != nil {
		t.Error("TestSignal could not signal process: ", e)
	}

	done := <-proc.Wait()
	if done != nil {
		t.Error("Failed to wait in TestSignal")
	}
	if proc.GetWaitStatus().String() != "signal: killed" {
		t.Error("Proc Was not signaled: ", proc.GetWaitStatus())
	}

}

func TestGetPid(t *testing.T) {
	proc := &Process{prog: "/bin/sleep", argv: []string{"2"}}
	if proc == nil {
		t.Error("Could not create process")
	}
	_, err := proc.Start()
	if err != nil {
		t.Error("TestSignal Failed to start process")
	}
	_, e := proc.Pid()
	if e != nil {
		t.Error("TestGetPid Error: ", e)
	}
}

func TestHasProc(t *testing.T) {
	proc := &Process{prog: "/bin/sleep", argv: []string{"2"}}
	if proc == nil {
		t.Error("Could not create process")
	}
	hasProc := proc.HasProc()
	if hasProc != false {
		t.Error("TestHasProc didn't return false for an unstarted process")
	}
}

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

package mproc

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/mproc/proc"
)

const (
	delay = 2
)

// MProc is a basic process manager
type MProc interface {
	// ManageProcess runs the process p and returns and id to use to refer to the process or an error
	// if ka is true, the process will be restarted up to retry times
	// If you want the process to restart indef. just use MaxUint32
	ManageProcess(p *proc.Process, ka bool, retry uint) (uint32, error)
	// KillAll sends SIGKILL all processes
	KillAll()
	// IntAll sends SIGINT to all processes
	IntAll()
	// EndKeepAlive stops the keep alive of process id
	EndKeepAlive(id uint32) error
	// SignalProc sends signal sig to process with id id
	SignalProc(id uint32, sig os.Signal) error
	// WaitProc waits on the process with the id id
	WaitProc(id uint32) chan error
	// GetProc gets the process with id id
	GetProc(id uint32) *proc.Process
	// KillProc kills the process with id id
	KillProc(id uint32) error
}

type mProc struct {
	mu           sync.Mutex
	managedProcs map[uint32]*managedP
	id           uint32
}

type managedP struct {
	p         *proc.Process
	mu        sync.Mutex
	keepAlive bool
	retry     uint
	remRetry  uint
}

// New creates a new MProc
func New() MProc {
	return &mProc{managedProcs: make(map[uint32]*managedP, 10)}

}

func create(p *proc.Process, keepAlive bool, retry uint) *managedP {
	return &managedP{p: p, keepAlive: keepAlive, retry: retry, remRetry: retry}
}

// KillAll sends SIGKILL all processes
func (mp *mProc) KillAll() {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	for _, v := range mp.managedProcs {
		log.Infoln("Killing: ", v)
		v.endKeepAlive()
		v.mu.Lock()
		v.p.Kill()
		v.mu.Unlock()
	}
}

// IntAll sends SIGINT to all processes
func (mp *mProc) IntAll() {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	for _, v := range mp.managedProcs {
		v.endKeepAlive()
		v.mu.Lock()
		v.p.Signal(syscall.SIGINT)
		v.mu.Unlock()
	}
}

// ManageProcess runs the process p and returns and id to use to refer to the process or an error
// if ka is true, the process will be restarted up to retry times
// If you want the process to restart indef. just use MaxUint32
func (mp *mProc) ManageProcess(p *proc.Process, ka bool, retry uint) (uint32, error) {

	if p == nil {
		return 0, errors.New("ManageProcess Argument nil: p")
	}
	defer mp.mu.Unlock()
	mp.mu.Lock()
	log.Infof("Starting process: %s", p.String())
	_, err := p.Start()
	if err != nil {
		return 0, err
	}
	manp := create(p, ka, retry)
	mp.managedProcs[mp.id] = manp
	if ka {
		mp.keepAlive(mp.id)
	}
	rid := mp.id
	mp.id = mp.id + 1
	return rid, err
}

func (mp *mProc) keepAlive(id uint32) {
	go func() {
		p := mp.getMp(id)
		err := <-p.p.Wait()
		log.Infof("Keep Alive just returned from wait")
		pid, e := p.p.Pid()
		if e != nil {
			log.Errorf("mProc Failed to get PID")
			return
		}
		if err == nil {
			ps := p.p.GetWaitStatus()
			log.Infof("KeepAlive Proc: %s, PID: %d stopped, status: %v",
				p.p.Prog(), pid, ps)

			mp.mu.Lock()
			defer mp.mu.Unlock()
			if p.keepAlive && p.remRetry > 0 {
				<-time.After(delay * time.Second)
				pid, err := p.p.Start()
				if err != nil {
					log.Error("Failed to restart process in keepAlive")
				}
				log.Infof("Restarted process: %s, PID: %d", p.p.Prog(), pid)
				p.remRetry--
				mp.keepAlive(id)
			}
			return
		}
		log.Errorf("mProc Failed to wait on PID: %d cannot restart", pid)

	}()
}
func (mp *managedP) endKeepAlive() {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.keepAlive = false
	mp.remRetry = 0
}

// EndKeepAlive stops the keep alive of process id
func (mp *mProc) EndKeepAlive(id uint32) error {
	p := mp.getMp(id)
	if p == nil {
		return fmt.Errorf("Error: Process with ID: %d does not exist", id)
	}

	pid, _ := p.p.Pid()
	log.Infof("Ending keep alive on PID: %d", pid)
	p.endKeepAlive()
	return nil
}

func (mp *mProc) getMp(id uint32) *managedP {
	defer mp.mu.Unlock()
	mp.mu.Lock()
	return mp.managedProcs[id]
}

// SignalProc sends signal sig to process with id id
func (mp *mProc) SignalProc(id uint32, sig os.Signal) error {
	pro := mp.GetProc(id)
	if pro == nil {
		return fmt.Errorf("Error: No proc with Id: %d", id)
	}
	return pro.Signal(sig)
}

// WaitProc waits on the process with the id id
func (mp *mProc) WaitProc(id uint32) chan error {
	proc := mp.GetProc(id)
	return proc.Wait()
}

// GetProc gets the process with id id
func (mp *mProc) GetProc(id uint32) *proc.Process {
	defer mp.mu.Unlock()
	mp.mu.Lock()
	p := mp.managedProcs[id]
	if p != nil {
		return p.p
	}
	return nil
}

// KillProc kills the process with id id
func (mp *mProc) KillProc(id uint32) error {
	proc := mp.GetProc(id)
	if proc == nil {
		return fmt.Errorf("Error: No proc with Id: %d", id)
	}
	return proc.Kill()
}

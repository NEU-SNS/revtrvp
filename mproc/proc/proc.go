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
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/NEU-SNS/revtrvp/log"
)

// Process represents a process
type Process struct {
	proc      *os.Process
	procAttr  *os.ProcAttr
	procState *os.ProcessState
	prog      string
	argv      []string
	mu        sync.Mutex
	started   bool
}

// New creates a new process
func New(p string, pA *os.ProcAttr, argv ...string) *Process {
	return &Process{prog: p, procAttr: pA, argv: argv}
}

// SetArg sets an argument
func (p *Process) SetArg(i int, arg string) error {
	if i > len(p.argv)-1 || i < 0 {
		return fmt.Errorf("Arg index out of range")
	}
	p.argv[i] = arg
	return nil
}

func (p *Process) String() string {
	s := fmt.Sprintf("Starting prog: %s with args %v", p.prog, p.argv)
	return s
}

// Prog gets the program name
func (p *Process) Prog() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prog
}

// Pid get the pid of the process
func (p *Process) Pid() (int, error) {

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proc != nil {
		return p.proc.Pid, nil
	}
	return 0, errors.New("The Process is not yet started")
}

// Start starts a process
func (p *Process) Start() (int, error) {

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return p.Pid()
	}
	if p.argv == nil {
		p.argv = []string{}
	}
	wd, _ := os.Getwd()
	if p.procAttr == nil {
		p.procAttr = &os.ProcAttr{
			Dir: wd,
			Files: []*os.File{
				os.Stdin,
				os.Stdout,
				os.Stderr,
			},
		}
	}
	log.Infof("Starting process: %s", p.prog)
	proc, err := os.StartProcess(p.prog,
		append([]string{p.prog}, p.argv...), p.procAttr)
	if err != nil {
		log.Errorf("Failed to start proc: %s error: %v", p.prog, err)
		return 0, err
	}
	p.proc = proc
	return p.proc.Pid, nil
}

// HasProc returns weather or not there is an os process associated
// with the process
func (p *Process) HasProc() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proc != nil
}

// Signal signals the process
func (p *Process) Signal(sig os.Signal) error {

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proc != nil {
		log.Infof("Signaling PID: %d with signal %v\n", p.proc.Pid, sig)

		return p.proc.Signal(sig)
	}

	return errors.New("Cannot Signal a process that hasn't started)")
}

// Kill kills the process
func (p *Process) Kill() error {

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proc != nil {
		log.Infof("Killing PID: %d", p.proc.Pid)
		res := p.proc.Kill()
		return res
	}

	return errors.New("Cannot Kill a process that hasn't started)")
}

// Wait waits on the process
func (p *Process) Wait() chan error {

	p.mu.Lock()
	defer p.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		log.Infof("Waiting on PID: %d", p.proc.Pid)
		p.mu.Lock()
		pr := p.proc
		p.mu.Unlock()
		state, err := pr.Wait()
		if err == nil {
			done <- err
		}
		p.mu.Lock()
		p.procState = state
		p.mu.Unlock()
		done <- nil
	}()

	return done
}

// GetWaitStatus gets the result of the OS wait syscall
func (p *Process) GetWaitStatus() *os.ProcessState {

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.procState == nil {
		return nil
	}

	ps := *p.procState

	return &ps

}

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
	"fmt"
	"io"
)

// CycleStart is the start of a warts cycle
type CycleStart struct {
	CycleID   uint32
	ListID    uint32
	CCycleID  uint32
	StartTime uint32
	PLength   uint16
	StopTime  uint32
	Hostname  string
}

func (c CycleStart) String() string {
	return fmt.Sprintf(
		"\nCycleID: %d\n"+
			"ListID: %d\n"+
			"Hostname: %s\n",
		c.CCycleID,
		c.ListID,
		c.Hostname,
	)
}

// CycleStartFlags are the flags that a CycleStart can contain
type CycleStartFlags struct {
	Length   uint16
	StopTime uint32
	Hostname string
}

// CycleStop is the end of a warts cycle
type CycleStop struct {
	CycleID  uint32
	StopTime uint32
}

// CycleStopFlags are the flags that a CycleStop can contain
type CycleStopFlags struct {
}

func readCycleStopFlags(f io.Reader) (CycleStopFlags, error) {
	first := make([]byte, 1)
	csf := CycleStopFlags{}
	n, err := f.Read(first)
	if err != nil {
		return csf, err
	}
	if n != 1 {
		return csf, fmt.Errorf("Failed to read, readCycleStopFlags")
	}
	return csf, nil
}

func readCycleStartFlags(f io.Reader) (CycleStartFlags, error) {
	first := make([]byte, 1)
	var stopTime bool
	var hostname bool
	var csf CycleStartFlags
	n, err := f.Read(first)
	if err != nil {
		return csf, fmt.Errorf("Failed to read cycle start flag: %v", err)
	}
	if n != 1 {
		return csf, fmt.Errorf("Bad Read readCycleStartFlags")
	}
	flag := first[0]
	if isset(flag, 1) {
		stopTime = true
	}
	if isset(flag, 2) {
		hostname = true
	}
	if !stopTime && !hostname {
		return csf, nil
	}
	l, err := readUint16(f)
	if err != nil {
		return csf, err
	}
	csf.Length = l
	if stopTime {
		n, err := readUint32(f)
		if err != nil {
			return csf, err
		}
		csf.StopTime = n
	}
	if hostname {
		hn, err := getString(f)
		if err != nil {
			return csf, err
		}
		csf.Hostname = hn
	}
	return csf, nil
}

func readCycle(f io.Reader) (CycleStart, error) {
	buf := make([]byte, 16)
	cycle := CycleStart{}
	n, err := f.Read(buf)
	if err != nil {
		return cycle, err
	}
	if n != 16 {
		return cycle, fmt.Errorf("Failed to read cycle")
	}
	cycle.CycleID = getUint32(buf[:4])
	cycle.ListID = getUint32(buf[4:8])
	cycle.CCycleID = getUint32(buf[8:12])
	cycle.StartTime = getUint32(buf[12:])
	fl, err := readCycleStartFlags(f)
	if err != nil {
		return cycle, err
	}
	cycle.Hostname = fl.Hostname
	cycle.PLength = fl.Length
	cycle.StopTime = fl.StopTime
	return cycle, nil
}

func readCycleStop(f io.Reader) (CycleStop, error) {
	cycle := CycleStop{}
	buf := make([]byte, 8)
	n, err := f.Read(buf)
	if err != nil {
		return cycle, err
	}
	if n != 8 {
		return cycle, fmt.Errorf("Failed to read Cycle stop")
	}
	cycle.CycleID = getUint32(buf[:4])
	cycle.StopTime = getUint32(buf[4:])
	_, err = readCycleStopFlags(f)
	if err != nil {
		return cycle, err
	}
	return cycle, nil
}

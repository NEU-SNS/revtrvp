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

// List is a warts list
type List struct {
	ListID      uint32
	CListID     uint32
	ListName    string
	PLength     uint16
	Description string
	MonitorName string
}

func (l List) String() string {
	return fmt.Sprintf(
		"\nListID: %d\n"+
			"List Name: %s\n"+
			"Description: %s\n"+
			"Monitor Name: %s\n",
		l.CListID,
		l.ListName,
		l.Description,
		l.MonitorName,
	)
}

// ListFlags are the flags a list can have
type ListFlags struct {
	Length      uint16
	Description string
	MonitorName string
}

func readList(f io.Reader) (List, error) {
	var list List
	ids := make([]byte, 8)
	n, err := f.Read(ids)
	if err != nil {
		return list, err
	}
	if n != 8 {
		return list, fmt.Errorf("readList short read")
	}
	list.ListID = getUint32(ids[:4])
	list.CListID = getUint32(ids[4:])
	name, err := getString(f)
	if err != nil {
		return list, err
	}
	list.ListName = name
	flags, err := readListFlags(f)
	if err != nil {
		return list, err
	}

	list.MonitorName = flags.MonitorName
	list.Description = flags.Description
	list.PLength = flags.Length
	return list, nil
}

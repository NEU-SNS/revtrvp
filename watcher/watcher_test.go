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

package watcher_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/NEU-SNS/revtrvp/util"
	"github.com/NEU-SNS/revtrvp/watcher"
)

func TestEvents(t *testing.T) {
	defer util.LeakCheck(t)()
	dir, err := ioutil.TempDir("", "watcher_test")
	if err != nil {
		t.Fatalf("Failed to create tmpdir")
	}
	defer os.RemoveAll(dir)
	w, err := watcher.New(dir)
	if err != nil {
		t.Fatalf("watcher.New(%s), Expected[<nil>], Got[%v]", dir, err)
	}
	defer w.Close()
	var added []string
	for _, test := range []struct {
		action watcher.EventType
		err    error
	}{
		{action: watcher.Create},
		{action: watcher.Create},
		{action: watcher.Remove},
		{action: watcher.Create},
		{action: watcher.Remove},
		{action: watcher.Remove},
	} {
		switch test.action {
		case watcher.Create:
			f, err := ioutil.TempFile(dir, "")
			if err != nil {
				t.Fatalf("Failed to create file: %v", err)
			}
			cancel := make(chan struct{})
			e, err := w.GetEvent(cancel)
			if err != test.err {
				t.Fatalf("w.GetEvent(), Expected[%v], Got[%v]", test.err, err)
			}
			if e.Type() != test.action {
				t.Fatalf("w.GetEvent(), Type: Expected[%v], Got[%v]", test.action, e.Type())
			}
			if e.Name() != f.Name() {
				t.Fatalf("w.GetEvent(), Name: Expected[%v], Got[%v]", f.Name(), e.Name())
			}
			added = append(added, f.Name())
			f.Close()
		case watcher.Remove:
			f := added[0]
			added = added[1:]
			os.Remove(f)
			cancel := make(chan struct{})
			e, err := w.GetEvent(cancel)
			if err != test.err {
				t.Fatalf("w.GetEvent(), Expected[%v], Got[%v]", test.err, err)
			}
			if e.Type() != test.action {
				t.Fatalf("w.GetEvent(), Type: Expected[%v], Got[%v]", test.action, e.Type())
			}
			if e.Name() != f {
				t.Fatalf("w.GetEvent(), Name: Expected[%v], Got[%v]", f, e.Name())
			}
		}
	}
}

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

package watcher

import (
	"fmt"

	"github.com/fsnotify/fsnotify"
)

// EventType represents a file system event
type EventType int

const (
	// Create is when a file is created
	Create EventType = iota
	// Remove is when a file is removed
	Remove
)

var (
	// ErrWatcherClosed is returned when the watcher is closed while waiting for an event
	ErrWatcherClosed = fmt.Errorf("The watcher was closed")
)

// Event represents a file system event
type Event interface {
	// Name gets the name of the file associated with the event
	Name() string
	// Type gets the event type
	// Currently only create and Remove events are supported
	Type() EventType
}

type event struct {
	e     fsnotify.Event
	etype EventType
}

func (e event) Name() string {
	return e.e.Name
}

func (e event) Type() EventType {
	return e.etype
}

type watcher struct {
	w *fsnotify.Watcher
}

// Watcher watches a path
type Watcher interface {
	// Close closes the watcher. The path watched by the watcher is no longer being
	// watched for events
	Close() error
	// GetEvent gets the next file system event. The call will block until an event occurs.
	// The call can be unblocked by closing the channel argument
	GetEvent(chan struct{}) (Event, error)
}

// New creates a new watcher which watches the given path
func New(path string) (Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	err = w.Add(path)
	if err != nil {
		return nil, err
	}
	return watcher{w: w}, nil
}

// Close closes the Watcher
func (w watcher) Close() error {
	return w.w.Close()
}

// GetEvent gets the next create/remove event
// Will stop watching when cancel is closed
func (w watcher) GetEvent(cancel chan struct{}) (Event, error) {
	for {
		select {
		case <-cancel:
			return nil, ErrWatcherClosed
		case ev, ok := <-w.w.Events:
			if !ok {
				return nil, ErrWatcherClosed
			}
			switch {
			case ev.Op&fsnotify.Create == fsnotify.Create:
				return event{e: ev, etype: Create}, nil
			case ev.Op&fsnotify.Remove == fsnotify.Remove:
				return event{e: ev, etype: Remove}, nil
			default:
				// We don't care about other events for now
				continue
			}
		case err := <-w.w.Errors:
			if err == nil {
				return nil, ErrWatcherClosed
			}
			return nil, err
		}
	}
}

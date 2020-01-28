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

// Package scamper is a library to work with scamper control sockets
package scamper

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type responseT string

const (
	ok   responseT = "OK"
	more responseT = "MORE"
	data responseT = "DATA"
	err  responseT = "ERR"
)

var (
	// ErrorBadDataResponse is returned when the data received by scamper couldnt
	// be converted
	ErrorBadDataResponse = errors.New("Bad DATA Response")
	// ErrorBadOKResponse is returned when an OK response fails to parse
	ErrorBadOKResponse = errors.New("Bad OK Response")
	// ErrorBadResponse is the generic error when a response can't be parsed
	ErrorBadResponse = errors.New("Bad Response")
	// ErrorTimeout returned when a command times out
	ErrorTimeout = errors.New("Timeout")
)

var (
	measurements = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "scamper_client_measurement_requests",
		Help: "The number of measurement requests sent to scamper",
	})
	measurementsErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "scamper_client_measurement_request_errors",
		Help: "The number of measurement requests that do not run due to an error",
	})
)

// Response represents a response from scamper
type Response struct {
	RType  responseT
	Data   []byte
	Ret    interface{}
	DS     int
	UserID uint32
	Err    error
	Header bool
}

// Bytes get the data as bytes from a scamper response
func (r Response) Bytes() []byte {
	return r.Data
}

// WriteTo writes the response to the given io.Writer
func (r Response) WriteTo(w io.Writer) (n int64, err error) {
	c, err := w.Write(r.Data)
	n = int64(c)
	return
}

var (
	// ErrorSocketNotFound is used when a socketMap doesn't contain a socket
	ErrorSocketNotFound = fmt.Errorf("No socket found")
)

type socketMap struct {
	sync.Mutex
	socks map[string]*Socket
}

func newSocketMap() *socketMap {
	s := make(map[string]*Socket)
	return &socketMap{socks: s}
}

func (sm *socketMap) Add(s *Socket) {
	sm.Lock()
	defer sm.Unlock()
	if so, ok := sm.socks[s.IP()]; ok {
		so.Stop()
	}
	sm.socks[s.IP()] = s
}

func (sm *socketMap) Remove(addr string) {
	sm.Lock()
	defer sm.Unlock()
	delete(sm.socks, addr)
}

func (sm *socketMap) Get(addr string) (*Socket, error) {
	sm.Lock()
	defer sm.Unlock()
	if sock, ok := sm.socks[addr]; ok {
		return sock, nil
	}
	return nil, ErrorSocketNotFound
}

func (sm *socketMap) GetAll() []*Socket {
	sm.Lock()
	defer sm.Unlock()
	var socks []*Socket
	for _, sock := range sm.socks {
		socks = append(socks, sock)
	}
	return socks
}

// Client is the main object for interacting with scamper
type Client struct {
	sockets *socketMap
}

// NewClient creates a new Client
func NewClient() *Client {
	return &Client{sockets: newSocketMap()}
}

// AddSocket adds a socket to the client
func (c *Client) AddSocket(s *Socket) {
	c.sockets.Add(s)
}

// RemoveSocket removes a socket from the client
func (c *Client) RemoveSocket(addr string) {
	c.sockets.Remove(addr)
}

// GetSocket gets a socket registered in the client
func (c *Client) GetSocket(addr string) (*Socket, error) {
	return c.sockets.Get(addr)
}

// GetAllSockets gets all the sockets
func (c *Client) GetAllSockets() <-chan *Socket {
	schan := make(chan *Socket)
	go func() {
		for _, sock := range c.sockets.GetAll() {
			schan <- sock
		}
		close(schan)
	}()
	return schan
}

// RemoveMeasurement removes a measurement
func (c *Client) RemoveMeasurement(addr string, id uint32) error {
	s, err := c.sockets.Get(addr)
	if err != nil {
		return nil
	}
	return s.RemoveMeasurement(id)
}

// DoMeasurement run the measurement described by arg from the address addr
func (c *Client) DoMeasurement(addr string, arg interface{}) (<-chan Response, uint32, error) {
	measurements.Inc()
	s, err := c.sockets.Get(addr)
	if err != nil {
		return nil, 0, err
	}
	ch, id, err := s.DoMeasurement(arg)
	if err != nil {
		measurementsErrors.Inc()
		return nil, 0, err
	}
	return ch, id, nil
}

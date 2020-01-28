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
	"bufio"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"sync/atomic"

	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/util"
	"github.com/NEU-SNS/revtrvp/uuencode"
	"github.com/NEU-SNS/revtrvp/warts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ErrorCmdNotFound returned when no cmd is found in the cmdMap
	ErrorCmdNotFound = fmt.Errorf("No command found matching given Id")
	// ErrorDupCommand returned when a socket as a cmd with the same id already
	// running
	ErrorDupCommand = fmt.Errorf("Command already exists with the give Id")
)

var (
	cmdsWritten = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scamper_socket_cmd_writes",
		Help: "The number of scamper cmds written.",
	}, []string{"vp"})
	cmdsRead = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scamper_socket_cmd_reads",
		Help: "The number of scamper cmds results read.",
	}, []string{"vp"})
	bytesWritten = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scamper_socket_bytes_written",
		Help: "The number of bytes written through the socket.",
	}, []string{"vp"})
	bytesRead = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scamper_socket_bytes_read",
		Help: "The number of bytes read from the socket.",
	}, []string{"vp"})
)

func init() {
	prometheus.MustRegister(cmdsWritten)
	prometheus.MustRegister(cmdsRead)
	prometheus.MustRegister(bytesWritten)
	prometheus.MustRegister(bytesRead)
}

type cmdMap struct {
	sync.Mutex
	cmds map[uint32]cmdResponse
}

type cmdResponse struct {
	cmd  Cmd
	done chan Response
}

func (cm *cmdMap) forEach() <-chan cmdResponse {
	c := make(chan cmdResponse)
	cm.Lock()
	go func() {
		defer cm.Unlock()
		for key, sock := range cm.cmds {
			delete(cm.cmds, key)
			c <- sock
		}
		close(c)
	}()
	return c
}

func (cm *cmdMap) getCmd(id uint32) (cmdResponse, error) {
	cm.Lock()
	defer cm.Unlock()
	if cmd, ok := cm.cmds[id]; ok {
		return cmd, nil
	}
	return cmdResponse{}, ErrorCmdNotFound
}

func (cm *cmdMap) rmCmd(id uint32) {
	cm.Lock()
	defer cm.Unlock()
	if _, ok := cm.cmds[id]; ok {
		delete(cm.cmds, id)
		return
	}
	log.Errorf("rmdCmd no cmd with id: %d", id)
}

func (cm *cmdMap) addCmd(c cmdResponse) error {
	cm.Lock()
	defer cm.Unlock()
	if _, ok := cm.cmds[c.cmd.ID]; ok {
		return ErrorDupCommand
	}
	cm.cmds[c.cmd.ID] = c
	return nil
}

func newCmdMap() *cmdMap {
	m := make(map[uint32]cmdResponse)
	return &cmdMap{cmds: m}
}

// Socket represents a scamper control socket
type Socket struct {
	fname       string
	ip          string
	port        string
	cmds        *cmdMap
	con         net.Conn
	wartsHeader [2]Response
	rc          uint32
	rw          *bufio.ReadWriter
	done        chan struct{}
	write       chan cmdResponse
	// Access atomically
	userID uint32
	mu     sync.Mutex // Protect state
	state  sockstate
}

type sockstate uint32

const (
	open sockstate = iota
	closed
)

// NewSocket creates a new scamper socket
func NewSocket(fname string, con net.Conn) (*Socket, error) {
	sock := &Socket{
		fname: fname,
		cmds:  newCmdMap(),
		con:   con,
		rw:    bufio.NewReadWriter(bufio.NewReader(con), bufio.NewWriter(con)),
		done:  make(chan struct{}),
		write: make(chan cmdResponse, 50),
	}

	go sock.readConn()
	go sock.writeConn()
	return sock, nil
}

// Stop closes the connection the socket represents
func (s *Socket) Stop() {
	log.Error("Closing socket")
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for cmd := range s.cmds.forEach() {
		close(cmd.done)
	}
	s.con.Close()
	if s.state == open {
		s.state = closed
		close(s.done)
	}
}

// Done indicates when the socket is closed
func (s *Socket) Done() <-chan struct{} {
	return s.done
}

type parseErr struct {
	err  error
	line string
}

func (e parseErr) Error() string {
	return fmt.Sprintf("Error parsing line %s: %v", e.line, e.err)
}

func (s *Socket) readResponse() (Response, error) {
	line, err := s.rw.ReadString('\n')
	if err != nil {
		return Response{}, err
	}
	resp, err := parseResponse(line, s.rw)
	if err != nil {
		return Response{}, parseErr{err: err, line: line}
	}
	if resp.RType != data {
		return resp, nil
	}
	// The first two data messages received are the header of the warts format
	if s.rc < 2 {
		s.wartsHeader[s.rc] = resp
		s.rc++
		resp.Header = true
	}
	return resp, nil
}

func (s *Socket) readConn() {
	var filter []warts.WartsT
	filter = append(filter, warts.PingT, warts.TracerouteT)
	count := cmdsRead.WithLabelValues(s.IP())
	bytes := bytesRead.WithLabelValues(s.IP())
	for {
		select {
		case <-s.done:
			return
		default:
		}
		resp, err := s.readResponse()
		if err != nil {
			s.handleErr(err)
			return
		}
		bytes.Add(float64(len(resp.Data)))
		count.Inc()
		if resp.Header {
			continue
		}
		switch resp.RType {
		case data:
			go func(r Response) {
				dec := &uuencode.UUDecodingWriter{}
				s.wartsHeader[0].WriteTo(dec)
				s.wartsHeader[1].WriteTo(dec)
				r.WriteTo(dec)
				res, err := warts.Parse(dec.Bytes(), filter)
				r.Err = err
				var cr cmdResponse
				if err == nil {
					switch t := res[0].(type) {
					case warts.Traceroute:
						r.UserID = t.Flags.UserID
					case warts.Ping:
						r.UserID = t.Flags.UserID
					}
					r.Ret = res[0]
					cr, err = s.cmds.getCmd(r.UserID)
					if err != nil {
						return
					}
					s.cmds.rmCmd(r.UserID)
				}
				cr.done <- r
			}(resp)
		default:
			continue
		}
	}
}

func (s *Socket) writeConn() {
	tick := time.NewTicker(time.Millisecond * 10)
	count := cmdsWritten.WithLabelValues(s.IP())
	bytes := bytesWritten.WithLabelValues(s.IP())
	var writes int
	for {
		select {
		case <-s.done:
			return
		case w := <-s.write:
			count.Inc()
			writes++
			err := w.cmd.IssueCommand(s.rw)
			if err != nil {
				log.Error(err)
				s.rw.Writer.Reset(s.con)
				writes = 0
				continue
			}
			if writes > 10 {
				bytes.Add(float64(s.rw.Writer.Buffered()))
				s.flushWrite()
				writes = 0
			}
		case <-tick.C:
			if s.rw.Writer.Buffered() > 0 {
				bytes.Add(float64(s.rw.Writer.Buffered()))
				s.flushWrite()
			}
		}
	}
}

func (s *Socket) flushWrite() {
	err := s.con.SetWriteDeadline(time.Now().Add(time.Second * 10))
	if err != nil {
		log.Error(err)
		s.rw.Writer.Reset(s.con)
		return
	}
	err = s.rw.Flush()
	for err == io.ErrShortWrite {
		err = s.rw.Flush()
	}
	if err != nil {
		log.Error(err)
		s.rw.Writer.Reset(s.con)
		return
	}
}

func (s *Socket) handleErr(err error) {
	s.Stop()
	log.Error(err)
}

func (s *Socket) getID() uint32 {
	return atomic.AddUint32(&s.userID, 1)
}

// RemoveMeasurement remove a measurment being run with id id
func (s *Socket) RemoveMeasurement(id uint32) error {
	s.cmds.rmCmd(id)
	return nil
}

var (
	// ErrSocketClosed is returned when the socket is closed
	ErrSocketClosed = fmt.Errorf("Socket closed.")
	// ErrFailedToIssueCmd is returned when issueCmd fails
	ErrFailedToIssueCmd = fmt.Errorf("Error issuing command.")
	// ErrSockClosed is returned when a measurement is attempted on a closed socket
)

// DoMeasurement perform the measurement described by arg
func (s *Socket) DoMeasurement(arg interface{}) (<-chan Response, uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == open {
		id := s.getID()
		cmd := Cmd{ID: id, Arg: arg}
		cr := cmdResponse{cmd: cmd, done: make(chan Response, 1)}
		err := s.cmds.addCmd(cr)
		if err != nil {
			return nil, 0, err
		}
		if err != nil {
			log.Error(err)
			s.cmds.rmCmd(id)
			return nil, 0, ErrFailedToIssueCmd
		}
		if err != nil {
			log.Error(err)
			s.cmds.rmCmd(id)
			return nil, 0, ErrFailedToIssueCmd
		}
		s.write <- cr
		return cr.done, id, nil
	}
	return nil, 0, ErrSocketClosed
}

// IP Gets the ip of the remote machine that is connected to the socket
func (s *Socket) IP() string {
	if s.ip == "" {
		s.ip = strings.Split(path.Base(s.fname), ":")[util.IP]
		return s.ip
	}
	return s.ip
}

// Port gets the port of the remote machine that is connected to the socket
func (s *Socket) Port() string {
	if s.port == "" {
		s.port = strings.Split(path.Base(s.fname), ":")[util.PORT]
		return s.port
	}
	return s.port
}

func parseResponse(r string, re io.Reader) (Response, error) {
	resp := Response{}
	switch {
	case strings.Contains(r, string(ok)):
		resp.RType = ok
		r = strings.TrimSpace(r)
		split := strings.Split(r, " ")
		idsp := strings.Split(split[1], "-")
		_, err := strconv.Atoi(idsp[1])
		if err != nil {
			return resp, ErrorBadResponse
		}
		return resp, nil
	case strings.Contains(r, string(err)):
		resp.RType = err
		return resp, nil
	case strings.Contains(r, string(data)):
		resp.RType = data
		split := strings.Split(r, " ")
		if len(split) != 2 {
			return resp, ErrorBadDataResponse
		}
		n, err := strconv.Atoi(split[1][:len(split[1])-1])
		if err != nil {
			return resp, err
		}
		resp.DS = n
		buff := make([]byte, n)
		_, err = io.ReadFull(re, buff)
		if err != nil {

			return resp, err
		}
		resp.Data = buff
		return resp, nil
	case strings.Contains(r, string(more)):
		resp.RType = more
		return resp, nil
	}
	return resp, ErrorBadResponse
}

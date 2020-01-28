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

//Package plcontroller is the library for creating a planet-lab controller
package plcontroller

import (
	"net"
	"path"
	"strings"

	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/scamper"
	"github.com/NEU-SNS/revtrvp/util"
	"github.com/NEU-SNS/revtrvp/watcher"
)

func (c *PlController) handlEvents() {
	c.clearAllVps()
	for {
		event, err := c.w.GetEvent(c.shutdown)
		if err == watcher.ErrWatcherClosed {
			return
		}
		if err != nil {
			log.Error(err)
			continue
		}
		switch event.Type() {
		case watcher.Create:
			log.Debugf("Create socket: %s", event.Name())
			con, err := net.Dial("unix", event.Name())
			if err != nil {
				log.Error(err)
				continue
			}
			s, err := scamper.NewSocket(
				event.Name(),
				con)
			if err != nil {
				log.Error(err)
				continue
			}
			ip, err := util.IPStringToInt32(s.IP())
			if err != nil {
				log.Errorf("Failed to convert socket IP: %v", err)
				s.Stop()
				continue
			}
			err = c.db.UpdateController(ip, c.ip, c.ip)
			if err != nil {
				log.Errorf("Failed to update controller  %v", err)
				s.Stop()
				continue
			}
			c.client.AddSocket(s)
			vpsConnected.Add(1)
		case watcher.Remove:
			log.Debugf("Remove socket: %s", event.Name())
			ip := strings.Split(path.Base(event.Name()), ":")[0]
			nip, err := util.IPStringToInt32(ip)
			if err != nil {
				log.Errorf("Failed to convert socket IP: %v", err)
				continue
			}
			err = c.db.UpdateController(nip, 0, c.ip)
			if err != nil {
				log.Errorf("Failed to update controller  %v", err)
			}
			sock, err := c.client.GetSocket(ip)
			if err != scamper.ErrorSocketNotFound {
				sock.Stop()
			}
			c.client.RemoveSocket(ip)
			vpsConnected.Sub(1)
		}
	}
}

func (c *PlController) clearAllVps() {
	err := c.db.ClearAllVPs()
	if err != nil {
		log.Error(err)
	}
}

//This is only for use when a server is going down
func (c *PlController) removeAllVps() {
	log.Debug("Removing all VPS")
	if c.client == nil {
		return
	}
	vps := c.client.GetAllSockets()
	log.Debug(vps)
	for sock := range vps {
		log.Debugf("Removing %v", sock.IP())
		ip, err := util.IPStringToInt32(sock.IP())
		if err != nil {
			log.Error(err)
			continue
		}
		err = c.db.UpdateController(ip, 0, c.ip)
		if err != nil {
			log.Error(err)
		}
	}
}

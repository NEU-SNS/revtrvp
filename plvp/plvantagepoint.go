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

// Package plvp is the library for creating a vantage poing on a planet-lab node
package plvp

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	dm "github.com/NEU-SNS/revtrvp/datamodel"
	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/mproc"
	plc "github.com/NEU-SNS/revtrvp/plcontroller/pb"
	"github.com/NEU-SNS/revtrvp/scamper"
	"github.com/NEU-SNS/revtrvp/util"
	"github.com/prometheus/client_golang/prometheus"
	ctx "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"net/http"
)

var (
	procCollector = prometheus.NewProcessCollectorPIDFn(func() (int, error) {
		return os.Getpid(), nil
	}, getName())
	spoofCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: getName(),
		Subsystem: "spoof",
		Name:      "count",
		Help:      "Count of the spoofed probes received",
	})
	Conf = NewConfig()
)

var id = rand.Uint32()

func getName() string {
	name, err := os.Hostname()
	if err != nil {
		return fmt.Sprintf("plvp_%d", id)
	}
	r := strings.NewReplacer(".", "_", "-", "")
	return fmt.Sprintf("plvp_%s", r.Replace(name))
}

func init() {
	prometheus.MustRegister(procCollector)
	prometheus.MustRegister(spoofCounter)
}

type SendCloser interface {
	Send([]*dm.Probe) error
	Close() error
}

type PLControllerSender struct {
	RootCA string
	conn   *grpc.ClientConn
}

func (cs *PLControllerSender) Send(ps []*dm.Probe) error {

	// Fast return if no probes to send.
	if len(ps) == 0 {
		log.Debug("No probes to send back")
		return nil
	}
	for _, p := range ps {
		srcs, _ := util.Int32ToIPString(p.Src)
		dsts, _ := util.Int32ToIPString(p.Dst)
		lgg := "Probe src: " + srcs + " dst: " + dsts
		lgg += " RR hops:"

		if p.GetRR() != nil {
			if p.GetRR().GetHops() != nil {
				for _, hop := range p.GetRR().GetHops() {
					hopstr, _ := util.Int32ToIPString(hop)
					lgg += hopstr + " "
				}
			}
		}

		log.Infof("Sending back to controller: " + lgg)
	}

	if cs.conn == nil {
		if *Conf.Environment.Debug {
			log.Infof("Connecting to plcontroller to %s %d", *Conf.Local.Host, *Conf.Local.Port)
			// Certificate is for the plcontroller.
			creds, err := credentials.NewClientTLSFromFile(cs.RootCA, "plcontroller.revtr.ccs.neu.edu")
			if err != nil {
				log.Error(err)
				return err
			}

			addr := fmt.Sprintf("%s:%d", *Conf.Local.Host, *Conf.Local.Port)

			cc, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
			if err != nil {
				log.Error(err)
				return err
			}
			cs.conn = cc

		} else {
			_, srvs, err := net.LookupSRV("plcontroller", "tcp", "revtr.ccs.neu.edu")
			log.Infof("Found %d plcontroller tcp services", len(srvs))
			if err != nil {
				log.Error(err)
				return err
			}
			for i, srv := range srvs {
				if i > 0 {
					// Allow only one connection to GRPC for now, but someday might be useful
					// if we have multiple controllers.
					break
				}
				log.Infof("Found service %s %d\n", srv.Target, srv.Port)
				creds, err := credentials.NewClientTLSFromFile(cs.RootCA, srv.Target)
				if err != nil {
					log.Error(err)
					continue
				}

				addr := fmt.Sprintf("%s:%d", srv.Target, srv.Port)

				cc, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
				if err != nil {
					log.Error(err)
					return err
				}
				cs.conn = cc
			}
		}
	}

	log.Debug("Establishing PLController conn...\n")
	client := plc.NewPLControllerClient(cs.conn)
	log.Debugf("PLController conn established.\n")
	contx, cancel := ctx.WithTimeout(ctx.Background(), time.Second*2)
	defer cancel()
	log.Debugf("calling AcceptProbes to server\n")
	_, err := client.AcceptProbes(contx, &dm.SpoofedProbes{Probes: ps})
	if err != nil {
		return err
	}

	return nil
}

func (cs *PLControllerSender) Close() error {
	if cs.conn != nil {
		err := cs.conn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type plVantagepointT struct {
	sc       scamper.Config
	spoofmon *SpoofPingMonitor
	mp       mproc.MProc
	config   Config
	mu       sync.Mutex
	monec    chan error
	monip    chan dm.Probe
	am       sync.Mutex // protect addr
	addr     string
	send     SendCloser
}

var plVantagepoint plVantagepointT

func (vp *plVantagepointT) handleSig(s os.Signal) {
	log.Infof("Got signal: %v", s)
	vp.stop()
}

func (vp *plVantagepointT) stop() {
	if vp.mp != nil {
		log.Infoln("Killing all processes")
		vp.mp.IntAll()
	}
	if vp.spoofmon != nil {
		vp.spoofmon.Quit()
	}
	if vp.send != nil {
		vp.send.Close()
	}
}

// HandleSig handles signals
func HandleSig(s os.Signal) {
	plVantagepoint.handleSig(s)
}

// The vp is dead if this method needs to return, so call stop() to clean up before returning
func (vp *plVantagepointT) run(c Config, s SendCloser, ec chan error) {
	vp.config = c
	con := new(scamper.Config)
	con.ScPath = *c.Scamper.BinPath
	con.IP = *c.Scamper.Host
	con.Port = *c.Scamper.Port
	con.Rate = *c.Scamper.Rate
	con.CAFile = *c.Scamper.CAFile

	err := scamper.ParseConfig(*con)
	if err != nil {
		log.Errorf("Invalid scamper args: %v", err)
		vp.stop()
		ec <- err
		return
	}
	sip, err := pickIP(*c.Scamper.Host)
	if err != nil {
		log.Errorf("Could not resolve url: %s, with err: %v", *c.Local.Host, err)
		vp.stop()
		ec <- err
		return
	}
	vp.send = s
	vp.addr = sip
	vp.sc = *con
	vp.mp = mproc.New()
	vp.spoofmon = NewSpoofPingMonitor()
	monaddr, err := util.GetBindAddr(*vp.config.Local.Interface)
	if err != nil {
		log.Errorf("Could not get bind addr: %v", err)
		vp.stop()
		ec <- err
		return
	}
	vp.monec = make(chan error, 10000)
	// Increase the size of the spoofing monitoring chanel
	vp.monip = make(chan dm.Probe, 100000)
	if !*c.Local.SenderOnly {
		go vp.spoofmon.Start(monaddr, plVantagepoint.monip, plVantagepoint.monec)
		go vp.monitorSpoofedPings(plVantagepoint.monip, plVantagepoint.monec)
	}
	if *c.Local.StartScamp {
		plVantagepoint.startScamperProcs()
	}
}

func startHTTP(addr string) {
	for {
		log.Error(http.ListenAndServe(addr, nil))
	}
}

// Start a plvp with the given config
func Start(c Config, s SendCloser) chan error {
	log.Info("Starting plvp with config: %v", c)
	http.Handle("/metrics", prometheus.Handler())
	go startHTTP(*c.Local.PProfAddr)
	errChan := make(chan error, 1)
	go plVantagepoint.run(c, s, errChan)
	return errChan

}

func (vp *plVantagepointT) monitorSpoofedPings(probes chan dm.Probe, ec chan error) {
	var sprobes []*dm.Probe
	ticker := time.NewTicker(time.Second)
	go func() {
		for {
			select {
			case probe := <-probes:
				spoofCounter.Inc()
				sprobes = append(sprobes, &probe)
			case err := <-ec:
				switch err {
				case ErrorNotICMPEcho, ErrorNonICMPEchoReply, ErrorNonSpoofedProbe:
					continue
				}
			case <-ticker.C:
				vp.send.Send(sprobes)
				sprobes = make([]*dm.Probe, 0)
			}
		}
	}()
}

func pickIP(host string) (string, error) {

	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}

	addrIndex := rand.Intn(len(addrs))
	addr := addrs[addrIndex]
	log.Debugf("Found IP address to bind %s to %s", host, addr)
	return addr, nil
}

func (vp *plVantagepointT) startScamperProcs() {
	log.Info("Starting scamper procs")
	sp := scamper.GetVPProc(vp.sc.ScPath, vp.sc.IP, vp.sc.Port, vp.sc.Rate, vp.sc.CAFile)
	vp.mp.ManageProcess(sp, true, math.MaxUint32)
}

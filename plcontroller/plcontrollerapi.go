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
	"fmt"
	"io"
	"sync"
	"time"

	dm "github.com/NEU-SNS/revtr-vp/datamodel"
	"github.com/NEU-SNS/revtr-vp/log"
	plc "github.com/NEU-SNS/revtr-vp/plcontroller/pb"
	con "golang.org/x/net/context"
)

var (
	// ErrorEmptyArgList is returned when a measurement request comes in with an
	// empty list of args
	ErrorEmptyArgList = fmt.Errorf("Empty argument list.")
	// ErrorNilArgList is returned when a measurement request comes in with a nil
	// argument list
	ErrorNilArgList = fmt.Errorf("Nil argument list.")
	// ErrorTimeout is returned when a measurement times out
	ErrorTimeout = fmt.Errorf("Measurement timed out.")
)

func (c *PlController) Ping(server plc.PLController_PingServer) error {
	ctx, cancel := con.WithCancel(server.Context())
	defer cancel()
	for {
		pa, err := server.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		pings := pa.GetPings()
		if pings == nil {
			return ErrorNilArgList
		}
		sendChan := make(chan *dm.Ping, len(pings))
		var wg sync.WaitGroup
		for _, ping := range pings {
			wg.Add(1)
			pingGoroutineGauge.Add(1)
			go func(p *dm.PingMeasurement) {
				start := time.Now()
				defer wg.Done()
				defer pingGoroutineGauge.Sub(1)
				pr, err := c.runPing(ctx, p)
				if err != nil {
					pr.Error = err.Error()
					pr.Src = p.Src
					pr.Dst = p.Dst
					pr.Start = &dm.Time{
						Sec:  int64(start.Second()),
						Usec: int64(start.Nanosecond() / 1000),
					}
				}
				select {
				case sendChan <- &pr:
				case <-ctx.Done():
				}
				done := time.Since(start).Seconds()
				if p.Spoof {
					if p.RR {
						ipOptionsResponseTimes.WithLabelValues("SPOOFED", "RR").Observe(done)
					}
					if p.TimeStamp != "" {
						ipOptionsResponseTimes.WithLabelValues("SPOOFED", "TS").Observe(done)
					}
				} else {
					if p.RR {
						ipOptionsResponseTimes.WithLabelValues("NON-SPOOFED", "RR").Observe(done)
					}
					if p.TimeStamp != "" {
						ipOptionsResponseTimes.WithLabelValues("NON-SPOOFED", "TS").Observe(done)
					}
				}
				pingResponseTimes.Observe(done)
			}(ping)
		}

		go func() {
			wg.Wait()
			close(sendChan)
		}()
		for {
			select {
			case p, ok := <-sendChan:
				if !ok {
					return nil
				}
				if err := server.Send(p); err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (c *PlController) Traceroute(server plc.PLController_TracerouteServer) error {
	ctx, cancel := con.WithCancel(server.Context())
	defer cancel()
	for {
		ta, err := server.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		traces := ta.GetTraceroutes()
		if traces == nil {
			return ErrorNilArgList
		}
		sendChan := make(chan *dm.Traceroute, len(traces))
		var wg sync.WaitGroup
		for _, trace := range traces {
			wg.Add(1)
			tracerouteGoroutineGauge.Add(1)
			go func(t *dm.TracerouteMeasurement) {
				start := time.Now()
				defer wg.Done()
				defer tracerouteGoroutineGauge.Sub(1)
				tr, err := c.runTraceroute(ctx, t)
				if err != nil {
					log.Debugf("Got tracerotue result: %v, with error %v", tr, err)
					tr.Error = err.Error()
					tr.Src = t.Src
					tr.Dst = t.Dst
					tr.Start = &dm.TracerouteTime{
						Sec:   int64(start.Second()),
						Usec:  int64(start.Nanosecond() / 1000),
						Ftime: dm.TTime(start).String(),
					}
				}
				select {
				case sendChan <- &tr:
				case <-ctx.Done():
				}
				done := time.Since(start).Seconds()
				tracerouteResponseTimes.Observe(done)
			}(trace)

		}
		go func() {
			wg.Wait()
			close(sendChan)
		}()
		for {
			select {
			case t, ok := <-sendChan:
				if !ok {
					return nil
				}
				if err := server.Send(t); err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (c *PlController) ReceiveSpoof(rs *dm.RecSpoof, stream plc.PLController_ReceiveSpoofServer) error {
	spoofs := rs.GetSpoofs()
	ctx, cancel := con.WithCancel(stream.Context())
	defer cancel()
	if spoofs == nil {
		return ErrorNilArgList
	}
	if len(spoofs) == 0 {
		return ErrorEmptyArgList
	}
	for _, spoof := range spoofs {
		ret, err := c.recSpoof(ctx, spoof)
		if err != nil {
			ret.Error = err.Error()
		}
		if err := stream.Send(ret); err != nil {
			return err
		}
	}
	return nil
}

func (c *PlController) AcceptProbes(ctx con.Context, probes *dm.SpoofedProbes) (*dm.SpoofedProbesResponse, error) {
	ps := probes.GetProbes()
	if ps == nil {
		return nil, ErrorNilArgList
	}
	if len(ps) == 0 {
		return nil, ErrorEmptyArgList
	}
	go func() {
		for _, p := range ps {
			err := c.acceptProbe(p)
			if err != nil {
				log.Errorf("%v %v", err, p)
			}
		}
	}()
	return &dm.SpoofedProbesResponse{}, nil
}

func (c *PlController) GetVPs(vpr *dm.VPRequest, stream plc.PLController_GetVPsServer) error {
	vps, err := c.db.GetActiveVPs()
	if err != nil {
		return nil
	}
	if err := stream.Send(&dm.VPReturn{Vps: vps}); err != nil {
		return err
	}
	return nil
}

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

// Package controller is the library for creating a central controller
package controller

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	cont "github.com/NEU-SNS/revtrvp/controller/pb"
	dm "github.com/NEU-SNS/revtrvp/datamodel"
	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/util"
	"github.com/gogo/protobuf/jsonpb"
	con "golang.org/x/net/context"
)

func (c *controllerT) Ping(pa *dm.PingArg, stream cont.Controller_PingServer) error {
	pms := pa.GetPings()
	if pms == nil {
		return nil
	}
	start := time.Now()
	ctx, cancel := con.WithCancel(stream.Context())
	defer cancel()
	res := c.doPing(ctx, pms)
	for {
		select {
		case p, ok := <-res:
			if !ok {
				end := time.Since(start).Seconds()
				pingResponseTimes.Observe(end)
				return nil
			}
			if err := stream.Send(p); err != nil {
				log.Error(err)
				end := time.Since(start).Seconds()
				pingResponseTimes.Observe(end)
				return err
			}
		case <-ctx.Done():
			end := time.Since(start).Seconds()
			pingResponseTimes.Observe(end)
			return ctx.Err()
		}
	}
}

func (c *controllerT) Traceroute(ta *dm.TracerouteArg, stream cont.Controller_TracerouteServer) error {
	tms := ta.GetTraceroutes()
	if tms == nil {
		return nil
	}
	start := time.Now()
	ctx, cancel := con.WithCancel(stream.Context())
	defer cancel()
	res := c.doTraceroute(ctx, tms)
	for {
		select {
		case t, ok := <-res:
			if !ok {
				end := time.Since(start).Seconds()
				tracerouteResponseTimes.Observe(end)
				return nil
			}
			if err := stream.Send(t); err != nil {
				log.Error(err)
				end := time.Since(start).Seconds()
				tracerouteResponseTimes.Observe(end)
				return err
			}
		case <-ctx.Done():
			end := time.Since(start).Seconds()
			tracerouteResponseTimes.Observe(end)
			return ctx.Err()
		}
	}
}

//Priority is the priority for ping request
type Priority uint32

//PingReq is a request for pings
type PingReq struct {
	Pings    []Ping   `json:"pings,omitempty"`
	Priority Priority `json:"priority,omitempty"`
}

// TraceReq is a request for traceroutes
type TraceReq struct {
	Traceroutes []Trace  `json:"traceroutes,omitempty"`
	Priority    Priority `json:"priority,omitempty"`
}

// Trace is an individual traceroute measurement
type Trace struct {
	Src      string `json:"src,omitempty"`
	Dst      string `json:"dst,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
}

//Ping is an individual measurement
type Ping struct {
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Count     int    `json:"count,omitempty"`
}

const (
	apiKey                = "Api-Key"
	v1Prefix              = "/api/v1/"
	maxProbeCount         = 4
	maxTracerouteAttempts = 4
)

func (c *controllerT) verifyKey(key string) (dm.User, bool) {
	u, err := c.db.GetUser(key)
	if err != nil {
		log.Error(err)
		return u, false
	}
	log.Debug("Got user ", u)
	return u, true
}

func (c *controllerT) GetPingsHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	key := req.Header.Get(apiKey)
	u, ok := c.verifyKey(key)
	if !ok {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	id := req.FormValue("id")
	idi, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		log.Error(err)
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	log.Debug("Getting pings for batch ", idi)
	pings, err := c.db.GetPingBatch(u, idi)
	if err != nil {
		log.Error(err)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	var marsh jsonpb.Marshaler
	if err := marsh.Marshal(rw, &dm.PingArgResp{Pings: pings}); err != nil {
		panic(err)
	}
}

func (c *controllerT) GetTracesHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	key := req.Header.Get(apiKey)
	u, ok := c.verifyKey(key)
	if !ok {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	id := req.FormValue("id")
	idi, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		log.Error(err)
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	log.Debug("Getting traces for batch ", idi)
	traces, err := c.db.GetTraceBatch(u, idi)
	if err != nil {
		log.Error(err)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	var marsh jsonpb.Marshaler
	if err := marsh.Marshal(rw, &dm.TracerouteArgResp{Traceroutes: traces}); err != nil {
		panic(err)
	}
}

func (c *controllerT) TracerouteHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	key := req.Header.Get(apiKey)
	u, ok := c.verifyKey(key)
	if !ok {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var treq TraceReq
	if err := json.NewDecoder(req.Body).Decode(&treq); err != nil {
		panic(err)
	}
	log.Debug("Running traces treq")
	var traces []*dm.TracerouteMeasurement
	for _, t := range treq.Traceroutes {
		if t.Attempts > maxTracerouteAttempts || t.Attempts < 0 {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		srci, err := util.IPStringToInt32(t.Src)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		dsti, err := util.IPStringToInt32(t.Dst)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if t.Attempts == 0 {
			t.Attempts = 2
		}
		traces = append(traces, &dm.TracerouteMeasurement{
			Src:      srci,
			Dst:      dsti,
			Attempts: fmt.Sprintf("%d", t.Attempts),
			Timeout:  20,
		})
	}
	if len(traces) == 0 {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	bid, err := c.db.AddTraceBatch(u)
	if err != nil {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	go func() {
		ctx := con.Background()
		ctx, cancel := con.WithTimeout(ctx, time.Second*30)
		defer cancel()
		results := c.doTraceroute(ctx, traces)
		var ids []int64
		for t := range results {
			ids = append(ids, t.Id)
		}
		err := c.db.AddTraceToBatch(bid, ids)
		if err != nil {
			log.Error(err)
		}
	}()
	rw.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(rw).Encode(struct {
		Results string `json:"results,omitempty"`
	}{Results: fmt.Sprintf("https://%s%s?id=%d", "revtr.ccs.neu.edu", v1Prefix+"traceroutes", bid)})
	if err != nil {
		panic(err)
	}
}

func (c *controllerT) PingHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPut {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	key := req.Header.Get(apiKey)
	u, ok := c.verifyKey(key)
	if !ok {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var preq PingReq
	if err := json.NewDecoder(req.Body).Decode(&preq); err != nil {
		panic(err)
	}
	var pings []*dm.PingMeasurement
	for _, p := range preq.Pings {
		if p.Count > maxProbeCount || p.Count <= 0 {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		srci, err := util.IPStringToInt32(p.Src)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		dsti, err := util.IPStringToInt32(p.Dst)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		pings = append(pings, &dm.PingMeasurement{
			Src:     srci,
			Dst:     dsti,
			Timeout: 10,
			Count:   fmt.Sprintf("%d", p.Count),
		})

	}
	bid, err := c.db.AddPingBatch(u)
	if err != nil {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	go func() {
		ctx := con.Background()
		ctx, cancel := con.WithTimeout(ctx, time.Second*30)
		defer cancel()
		results := c.doPing(ctx, pings)
		var ids []int64
		for p := range results {
			ids = append(ids, p.Id)
		}
		err := c.db.AddPingsToBatch(bid, ids)
		if err != nil {
			log.Error(err)
		}
	}()
	rw.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(rw).Encode(struct {
		Results string `json:"results,omitempty"`
	}{Results: fmt.Sprintf("https://%s%s?id=%d", "revtr.ccs.neu.edu", v1Prefix+"pings", bid)})
	if err != nil {
		panic(err)
	}
}

func (c *controllerT) RecordRouteHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	key := req.Header.Get(apiKey)
	u, ok := c.verifyKey(key)
	if !ok {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var preq PingReq
	if err := json.NewDecoder(req.Body).Decode(&preq); err != nil {
		panic(err)
	}
	log.Debug("Running record routes ", preq)
	var pings []*dm.PingMeasurement
	for _, p := range preq.Pings {
		srci, err := util.IPStringToInt32(p.Src)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		dsti, err := util.IPStringToInt32(p.Dst)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		pings = append(pings, &dm.PingMeasurement{
			Src:     srci,
			Dst:     dsti,
			Timeout: 10,
			Count:   "1",
			RR:      true,
		})
	}
	if len(pings) == 0 {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	bid, err := c.db.AddPingBatch(u)
	if err != nil {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	go func() {
		ctx := con.Background()
		ctx, cancel := con.WithTimeout(ctx, time.Second*30)
		defer cancel()
		results := c.doPing(ctx, pings)
		var ids []int64
		for p := range results {
			ids = append(ids, p.Id)
		}
		err := c.db.AddPingsToBatch(bid, ids)
		if err != nil {
			log.Error(err)
		}
	}()
	rw.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(rw).Encode(struct {
		Results string `json:"results,omitempty"`
	}{Results: fmt.Sprintf("https://%s%s?id=%d", "revtr.ccs.neu.edu", v1Prefix+"pings", bid)})
	if err != nil {
		panic(err)
	}
}

func (c *controllerT) TimeStampHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	key := req.Header.Get(apiKey)
	u, ok := c.verifyKey(key)
	if !ok {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var preq PingReq
	if err := json.NewDecoder(req.Body).Decode(&preq); err != nil {
		panic(err)
	}
	var pings []*dm.PingMeasurement
	for _, p := range preq.Pings {
		if p.Timestamp == "" {
			rw.Header().Set("Content-Type", "text/plain")
			http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		srci, err := util.IPStringToInt32(p.Src)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		dsti, err := util.IPStringToInt32(p.Dst)
		if err != nil {
			rw.Header().Set("Content-Type", "text/plain")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		pings = append(pings, &dm.PingMeasurement{
			Src:       srci,
			Dst:       dsti,
			Timeout:   10,
			Count:     "1",
			TimeStamp: p.Timestamp,
		})
	}
	if len(pings) == 0 {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	bid, err := c.db.AddPingBatch(u)
	if err != nil {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	go func() {
		ctx := con.Background()
		ctx, cancel := con.WithTimeout(ctx, time.Second*30)
		defer cancel()
		results := c.doPing(ctx, pings)
		var ids []int64
		for p := range results {
			log.Debug("Got timestamp ", p)
			ids = append(ids, p.Id)
		}
		err := c.db.AddPingsToBatch(bid, ids)
		if err != nil {
			log.Error(err)
		}
	}()
	rw.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(rw).Encode(struct {
		Results string `json:"results,omitempty"`
	}{Results: fmt.Sprintf("https://%s%s?id=%d", "revtr.ccs.neu.edu", v1Prefix+"pings", bid)})
	if err != nil {
		panic(err)
	}
}

type vps struct {
	IP string
}

type vpret struct {
	VPS []vps
}

func (c *controllerT) VPSHandler(rw http.ResponseWriter, req *http.Request) {
	key := req.Header.Get(apiKey)
	_, ok := c.verifyKey(key)
	if !ok {
		rw.Header().Set("Content-Type", "text/plain")
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	ctx := con.Background()
	ctx, cancel := con.WithTimeout(ctx, time.Second*30)
	defer cancel()
	vpr, err := c.doGetVPs(ctx, &dm.VPRequest{})
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	var ret vpret
	for _, vp := range vpr.GetVps() {
		ips, _ := util.Int32ToIPString(vp.Ip)
		ret.VPS = append(ret.VPS, vps{IP: ips})
	}
	rw.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(rw).Encode(ret)
	if err != nil {
		panic(err)
	}
	return
}

func (c *controllerT) GetVPs(ctx con.Context, gvp *dm.VPRequest) (vpr *dm.VPReturn, err error) {
	vpr, err = c.doGetVPs(ctx, gvp)
	return
}

func (c *controllerT) ReceiveSpoofedProbes(probes cont.Controller_ReceiveSpoofedProbesServer) error {
	log.Debug("ReceiveSpoofedProbes")
	for {
		pr, err := probes.Recv()
		if err == io.EOF {
			return probes.SendAndClose(&dm.ReceiveSpoofedProbesResponse{})
		}
		if err != nil {
			log.Error(err)
			return err
		}
		c.doRecSpoof(probes.Context(), pr)
	}
}

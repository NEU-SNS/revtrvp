/*
 Copyright (c) 2015, Northeastern University
, r All rights reserved.

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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
    "bytes"

	ca "github.com/NEU-SNS/revtr-vp/cache"
	"github.com/NEU-SNS/revtr-vp/controller/pb"
	dm "github.com/NEU-SNS/revtr-vp/datamodel"
	"github.com/NEU-SNS/revtr-vp/log"
	"github.com/NEU-SNS/revtr-vp/router"
	"github.com/NEU-SNS/revtr-vp/util"
	"github.com/prometheus/client_golang/prometheus"
	con "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	nameSpace     = "controller"
	procCollector = prometheus.NewProcessCollectorPIDFn(func() (int, error) {
		return os.Getpid(), nil
	}, nameSpace)
	rpcCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "rpc",
		Name:      "count",
		Help:      "Count of Rpc Calls sent",
	})
	timeoutCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "rpc",
		Name:      "timeout_count",
		Help:      "Count of Rpc Timeouts",
	})
	errorCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "rpc",
		Name:      "error_count",
		Help:      "Count of Rpc Errors",
	})
	pingResponseTimes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: nameSpace,
		Subsystem: "measurements",
		Name:      "ping_response_times",
		Help:      "The time it takes for pings to respond",
	})
	tracerouteResponseTimes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: nameSpace,
		Subsystem: "measurements",
		Name:      "traceroute_response_times",
		Help:      "The time it takes for traceroutes to respond",
	})
	pingsFromCache = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "cache",
		Name:      "pings_from_cache",
		Help:      "The number of pings retrieved from the cache.",
	})
	pingsFromDB = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "db",
		Name:      "pings_from_db",
		Help:      "The number of pings retrieved from the db.",
	})
	tracesFromCache = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "cache",
		Name:      "traces_from_cache",
		Help:      "The number of traceroutes retrieved from the cache.",
	})
	tracesFromDB = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "db",
		Name:      "traces_from_db",
		Help:      "The number of traceroutes retrieved from the db.",
	})
)

func init() {
	prometheus.MustRegister(procCollector)
	prometheus.MustRegister(rpcCounter)
	prometheus.MustRegister(timeoutCounter)
	prometheus.MustRegister(errorCounter)
	prometheus.MustRegister(pingResponseTimes)
	prometheus.MustRegister(tracerouteResponseTimes)
	prometheus.MustRegister(pingsFromCache)
	prometheus.MustRegister(pingsFromDB)
	prometheus.MustRegister(tracesFromCache)
	prometheus.MustRegister(tracesFromDB)
}

// DataAccess defines the interface needed by a DB
type DataAccess interface {
	GetPingBySrcDst(src, dst uint32) ([]*dm.Ping, error)
	GetPingsMulti([]*dm.PingMeasurement) ([]*dm.Ping, error)
	StorePing(*dm.Ping) (int64, error)
	GetTRBySrcDst(uint32, uint32) ([]*dm.Traceroute, error)
	GetTraceMulti([]*dm.TracerouteMeasurement) ([]*dm.Traceroute, error)
	StoreTraceroute(*dm.Traceroute) (int64, error)
	Close() error
	GetUser(string) (dm.User, error)
	AddPingBatch(dm.User) (int64, error)
	AddPingsToBatch(int64, []int64) error
	GetPingBatch(dm.User, int64) ([]*dm.Ping, error)
	AddTraceBatch(dm.User) (int64, error)
	AddTraceToBatch(int64, []int64) error
	GetTraceBatch(dm.User, int64) ([]*dm.Traceroute, error)
}

type controllerT struct {
	config  Config
	db      DataAccess
	cache   ca.Cache
	router  router.Router
	server  *grpc.Server
	spoofID uint32
	sm      *spoofMap
}

var controller controllerT

func (c *controllerT) nextSpoofID() uint32 {
	return atomic.AddUint32(&(c.spoofID), 1)
}

// HandleSig handles and signals received from the OS
func HandleSig(sig os.Signal) {
	controller.handleSig(sig)
}

func (c *controllerT) handleSig(sig os.Signal) {
	log.Infof("Got signal: %v", sig)
	c.stop()
}

func (c *controllerT) startRPC(eChan chan error) {
	addr := fmt.Sprintf("%s:%d", *c.config.Local.Addr,
		*c.config.Local.Port)
	log.Infof("Conecting to: %s", addr)
	l, e := net.Listen("tcp", addr)
	if e != nil {
		log.Errorf("Failed to listen: %v", e)
		eChan <- e
		return
	}
	log.Infof("Controller started, listening on: %s", addr)
	err := c.server.Serve(l)
	if err != nil {
		eChan <- err
	}
}

func errorAllPing(ctx con.Context, err error, out chan<- *dm.Ping, ps []*dm.PingMeasurement) {
	for _, p := range ps {
		select {
		case out <- &dm.Ping{
			Src:   p.Src,
			Dst:   p.Dst,
			Error: err.Error(),
		}:
		case <-ctx.Done():
		}
	}
}

func errorAllTrace(ctx con.Context, err error, out chan<- *dm.Traceroute, ts []*dm.TracerouteMeasurement) {
	for _, t := range ts {
		select {
		case out <- &dm.Traceroute{
			Src:   t.Src,
			Dst:   t.Dst,
			Error: err.Error(),
		}:
		case <-ctx.Done():
		}
	}
}

var (
	// ErrTimeout is used when the done channel on a context is received from
	ErrTimeout = fmt.Errorf("Request timeout")
)

func checkPingCache(ctx con.Context, keys []string, c ca.Cache) (map[string]*dm.Ping, error) {
	log.Debug("Checking for pings in cache: ", keys)
	out := make(chan map[string]*dm.Ping, 1)
	quit := make(chan struct{})
	eout := make(chan error, 1)
	go func() {
		found := make(map[string]*dm.Ping)
		res, err := c.GetMulti(keys)
		if err != nil {
			log.Error(err)
			eout <- err
			return
		}
        log.Debug("\n \n GET MULTI OUTPUT: \n \n: ", res)
		for key, item := range res {
            log.Debug("\n \n PRINT ITEM VALUE ***: ", key, item.Value())
            if bytes.Equal(item.Value(), []byte{'x'}) {
                log.Debug("\n \n DUMMY VALUE REACHED \n \n")
                ping := &dm.Ping {}
                pingsFromCache.Inc()
                found[key] = ping
            } else {
			    ping := &dm.Ping{}
			    err := ping.CUnmarshal(item.Value())
			    if err != nil {
				    log.Error(err)
				    continue
			    }
			    pingsFromCache.Inc()
			    found[key] = ping
            }
		}
		select {
		case <-quit:
			return
		case out <- found:
		}
	}()
	select {
	case <-ctx.Done():
		close(quit)
		return nil, ErrTimeout
	case ret := <-out:
		log.Debug("Got from ping cache: ", ret)
		return ret, nil
	case err := <-eout:
		return nil, err
	}
}

func checkPingDb(ctx con.Context, check []*dm.PingMeasurement, db DataAccess) (map[string]*dm.Ping, error) {
	out := make(chan map[string]*dm.Ping, 1)
	quit := make(chan struct{})
	eout := make(chan error, 1)
	go func() {
		foundMap := make(map[string]*dm.Ping)
		found, err := db.GetPingsMulti(check)
		if err != nil {
			log.Error(err)
			eout <- err
		}
		for _, p := range found {
			log.Debug("Got ping from db: ", p)
			pingsFromDB.Inc()
			foundMap[p.Key()] = p
		}
		select {
		case <-quit:
			return
		case out <- foundMap:
		}
	}()
	select {
	case <-ctx.Done():
		close(quit)
		return nil, ErrTimeout
	case ret := <-out:
		return ret, nil
	case err := <-eout:
		return nil, err
	}
}

func (c *controllerT) doPing(ctx con.Context, pm []*dm.PingMeasurement) <-chan *dm.Ping {
	ret := make(chan *dm.Ping, len(pm))
	go func() {
		var checkCache = make(map[string]*dm.PingMeasurement)
		var remaining []*dm.PingMeasurement
		var cacheKeys []string
		for _, pm := range pm {
			if pm.CheckCache && pm.TimeStamp == "" {
				key := pm.Key()
				checkCache[key] = pm
				cacheKeys = append(cacheKeys, key)
				continue
			}
			remaining = append(remaining, pm)
		}
		var found map[string]*dm.Ping
		if len(cacheKeys) > 0 {
			var err error
			found, err = checkPingCache(ctx, cacheKeys, c.cache)
			if err != nil {
				log.Error(err)
			}
		}
		// Figure out what we got vs what we asked for
		for key, val := range checkCache {
			// For each one that we looked for,
			// If it was found, send it back,
			// Otherwise, add it to the remaining list
			if p, ok := found[key]; ok {
                if (p == &dm.Ping{}) {
                    log.Debug("\n \n DUMMY VALUE SKIPPED \n \n")
                    continue
                } else {
                    log.Debug("sending: ", p)
                    ret <- p
                }
			} else {
				remaining = append(remaining, val)
			}
		}
		var checkDb = make(map[string]*dm.PingMeasurement)
		var checkDbArg []*dm.PingMeasurement
		working := remaining
		remaining = nil
		for _, pm := range working {
			if pm.CheckDb && pm.TimeStamp == "" {
				checkDb[pm.Key()] = pm
				checkDbArg = append(checkDbArg, pm)
				continue
			}
			remaining = append(remaining, pm)
		}
		dbs, err := checkPingDb(ctx, checkDbArg, c.db)
		if err != nil {
			log.Error(err)
		}
		// Again figure out what we got out of what we asked for
		for key, val := range checkDb {
			if p, ok := dbs[key]; ok {
				//This should be stored in the cache
				go func() {
					var err = c.cache.SetWithExpire(key, p.CMarshal(), 15*60)
					if err != nil {
						log.Info(err)
					}
				}()
				ret <- p
			} else {
				remaining = append(remaining, val)
			}
		}
		//Remaining are the measurements that need to be run
		var spoofs []*dm.PingMeasurement
		old := remaining
		remaining = nil
        // separates measurements that need to be spoofed with
        // those that don't need to be spoofed
		for _, pm := range old {
			if pm.Spoof {
				spoofs = append(spoofs, pm)
			} else {
				remaining = append(remaining, pm)
			}
		}
		mts := make(map[router.ServiceDef][]*dm.PingMeasurement)
		for _, pm := range remaining {
			ip, _ := util.Int32ToIPString(pm.Src)
			sd, err := c.router.GetService(ip)
			if err != nil {
				log.Error(err)
				ret <- &dm.Ping{
					Src:   pm.Src,
					Dst:   pm.Dst,
					Error: err.Error(),
				}
				continue
			}
			mts[sd] = append(mts[sd], pm)
		}
		var wg sync.WaitGroup
		for sd, pms := range mts {
			wg.Add(1)
			go func(s router.ServiceDef, meas []*dm.PingMeasurement) {
				defer wg.Done()
				mt, err := c.router.GetMT(s)
				if err != nil {
					log.Error(err)
					errorAllPing(ctx, err, ret, meas)
					return
				}
				defer mt.Close()
				pc, err := mt.Ping(ctx, &dm.PingArg{
					Pings: meas,
				})
				if err != nil {
					log.Error(err)
					errorAllPing(ctx, err, ret, meas)
					return
				}
				for {
					select {
					case <-ctx.Done():
						return
					case pp, ok := <-pc:
						if !ok {
							return
						}
						if pp == nil {
							return
						}
						id, err := c.db.StorePing(pp)
						if err != nil {
							log.Error(err)
						}
                        if len(pp.GetResponses()) == 0 {
                            log.Debug("\n \n PING GOT NO RESPONSES \n \n")
                            notFound := []byte{'x'}
                            err = c.cache.SetWithExpire(pp.Key(), notFound, 15*60)
                            if err != nil {
                                log.Error(err)
                            }
                            resX, err := c.cache.Get(pp.Key())
                            if err != nil {
                                log.Error(err)
                            }
                            log.Debug("\n \n CACHE VALUE: ", resX)
                        } else {
						    err = c.cache.SetWithExpire(pp.Key(), pp.CMarshal(), 15*60)
						    if err != nil {
							    log.Error(err)
						    }
                        }
						pp.Id = id
						log.Debug("Sending: ", pp)
						select {
						case ret <- pp:
						case <-ctx.Done():
							return
						}
					}
				}
			}(sd, pms)
		}
		sdForSpoof := make(map[router.ServiceDef][]*dm.Spoof)
		sdForSpoofP := make(map[router.ServiceDef][]*dm.PingMeasurement)
		var spoofIds []uint32
		for _, sp := range spoofs {
			ip, _ := util.Int32ToIPString(sp.Src)
			sd, err := c.router.GetService(ip)
			if err != nil {
				log.Error(err)
				ret <- &dm.Ping{
					Src:   sp.Src,
					Dst:   sp.Dst,
					Error: err.Error(),
				}
				continue
			}
			ips, _ := util.Int32ToIPString(sp.SpooferAddr)
			sds, err := c.router.GetService(ips)
			if err != nil {
				log.Error(err)
				ret <- &dm.Ping{
					Src:   sp.Src,
					Dst:   sp.Dst,
					Error: err.Error(),
				}
				continue
			}
			sdForSpoofP[sd] = append(sdForSpoofP[sd], sp)
			id := c.nextSpoofID()
			sp.Payload = fmt.Sprintf("%08x", id)
			spoofIds = append(spoofIds, id)
			log.Debug("Creating dm.Spoof for: ", *sp)
			sa, err := util.IPStringToInt32(sp.SAddr)
			if err != nil {
				log.Error(err)
				continue
			}
			sdForSpoof[sds] = append(sdForSpoof[sds], &dm.Spoof{
				Ip:  sp.Src,
				Id:  id,
				Sip: sa,
				Dst: sp.Dst,
			})

		}
		rChan := make(chan *dm.Probe, len(spoofIds))
		kill := make(chan struct{})
		if len(spoofIds) != 0 {
			c.sm.Add(rChan, kill, spoofIds)
		} else {
			// This is ugly but prevent waiting for no reason
			close(rChan)
		}
		for sd, spoofs := range sdForSpoof {
			wg.Add(1)
			go func(s router.ServiceDef, sps []*dm.Spoof) {
				defer wg.Done()
				mt, err := c.router.GetMT(s)
				if err != nil {
					log.Error(err)
					return
				}
				defer mt.Close()
				resp, err := mt.ReceiveSpoof(ctx, &dm.RecSpoof{
					Spoofs: sps,
				})
				if err != nil {
					log.Error(err)
					return
				}
				for _ = range resp {
				}
			}(sd, spoofs)
		}
		for sd, spoofs := range sdForSpoofP {
			wg.Add(1)
			go func(s router.ServiceDef, sps []*dm.PingMeasurement) {
				defer wg.Done()
				mt, err := c.router.GetMT(s)
				if err != nil {
					log.Error(err)
					return
				}
				defer mt.Close()
				resp, err := mt.Ping(ctx, &dm.PingArg{
					Pings: sps,
				})
				if err != nil {
					log.Error(err)
					return
				}
				for _ = range resp {

				}
			}(sd, spoofs)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					close(kill)
					return
				case probe, ok := <-rChan:
					if !ok {
						close(kill)
						return
					}
					if probe == nil {
						close(kill)
						return
					}
					px, x := toPing(probe)
					log.Debug("Caching spoofed result with key: ", px.Key())
                    if x == 1 {
                        notFound := []byte{'x'}
                        log.Debug("\n \n CREATING DUMMY VALUE \n \n", notFound)
                        err := c.cache.SetWithExpire(px.Key(), notFound, 15*60)
                        if err != nil {
                            log.Error(err)
                        }
                        resX, err := c.cache.Get(px.Key())
                        if err != nil {
                            log.Error(err)
                        }
                        log.Debug("\n \n CACHE VALUE: :", resX)
                        select {
                        case <-ctx.Done():
                            close(kill)
                            return
                        case ret <- px:
                        }
                    } else {
					    err := c.cache.SetWithExpire(px.Key(), px.CMarshal(), 15*60)
					    if err != nil {
						    log.Error(err)
					    }
					    pid, err := c.db.StorePing(px)
					    if err != nil {
						    log.Error(err)
					    }
					    px.Id = pid
					    select {
					    case <-ctx.Done():
						    close(kill)
						    return
					    case ret <- px:
					    }
                    }
				}
			}
		}()
		wg.Wait()
		close(ret)
	}()

	return ret
}

func toPing(probe *dm.Probe) (*dm.Ping, int) {
	var ping dm.Ping
	// Ping src and dst are reversed from the probe
	// since the probe is a response from a ping
	// Ping srcs and dsts are from the measurement
	// not the response
	ping.Src = probe.Dst
	ping.Dst = probe.Src
	ping.SpoofedFrom = probe.SpooferIp
	ping.Flags = append(ping.Flags, "spoof")
	var pr dm.PingResponse
	tx := &dm.Time{}
	now := time.Now().Unix()
	tx.Sec = now
	pr.Tx = tx
	rx := &dm.Time{}
	rx.Sec = now
	pr.Rx = rx
	pr.From = probe.Src
	rrs := probe.GetRR()
    x := 0
	if rrs != nil {
        //if len(rrs.Hops) == 0 {
        //    log.Debug("\n \n NO RECORD ROUTE HOPS FOUND \n \n")
        //    ping.Flags = append(ping.Flags, "v4rr")
        //    pr.RR = []uint32{}
        //    ping.Responses = []*dm.PingResponse{&pr}
        //    x = 1
		ping.Flags = append(ping.Flags, "v4rr")
		pr.RR = rrs.Hops
		ping.Responses = []*dm.PingResponse{&pr}
	} else {
        log.Debug("\n \n RRS NIL \n \n")
        ping.Flags = append(ping.Flags, "v4rr")
        pr.RR = []uint32{}
        ping.Responses = []*dm.PingResponse{&pr}
        x = 1
    }
	ts := probe.GetTs()
	if ts != nil {
		switch ts.Type {
		case dm.TSType_TSOnly:
			ping.Flags = append(ping.Flags, "tsonly")
			stamps := ts.GetStamps()
			var ts []uint32
			for _, stamp := range stamps {
				ts = append(ts, stamp.Time)
			}
			pr.Tsonly = ts
		default:
			stamps := ts.GetStamps()
			var ts []*dm.TsAndAddr
			if stamps != nil {

				ping.Flags = append(ping.Flags, "tsandaddr")
				for _, stamp := range stamps {
					ts = append(ts, &dm.TsAndAddr{
						Ip: stamp.Ip,
						Ts: stamp.Time,
					})
				}
				pr.Tsandaddr = ts
			}
		}
		ping.Responses = []*dm.PingResponse{
			&pr}
	}
	return &ping, x
}

func (c *controllerT) doRecSpoof(ctx con.Context, pr *dm.Probe) {
	c.sm.Notify(pr)
}

func checkTraceCache(ctx con.Context, keys []string, ca ca.Cache) (map[string]*dm.Traceroute, error) {
	log.Debug("Checking for traceroute in cache: ", keys)
	out := make(chan map[string]*dm.Traceroute, 1)
	eout := make(chan error, 1)
	go func() {
		found := make(map[string]*dm.Traceroute)
		res, err := ca.GetMulti(keys)
		if err != nil {
			log.Error(err)
			select {
			case eout <- err:
			case <-ctx.Done():
				return
			}
		}
		for key, item := range res {
			trace := &dm.Traceroute{}
			err := trace.CUnmarshal(item.Value())
			if err != nil {
				log.Error(err)
				continue
			}
			tracesFromCache.Inc()
			found[key] = trace
		}
		select {
		case <-ctx.Done():
		case out <- found:
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ErrTimeout
	case ret := <-out:
		log.Debug("Got from traceroute cache: ", ret)
		return ret, nil
	case err := <-eout:
		return nil, err
	}
}

func checkTraceDb(ctx con.Context, check []*dm.TracerouteMeasurement, db DataAccess) (map[string]*dm.Traceroute, error) {
	out := make(chan map[string]*dm.Traceroute, 1)
	quit := make(chan struct{})
	eout := make(chan error, 1)
	go func() {
		foundMap := make(map[string]*dm.Traceroute)
		found, err := db.GetTraceMulti(check)
		if err != nil {
			log.Error(err)
			select {
			case eout <- err:
			case <-ctx.Done():
			}
			return
		}
		for _, p := range found {
			tracesFromDB.Inc()
			foundMap[p.Key()] = p
		}
		select {
		case <-quit:
		case out <- foundMap:
		case <-ctx.Done():
		}
	}()
	select {
	case <-ctx.Done():
		close(quit)
		return nil, ErrTimeout
	case ret := <-out:
		return ret, nil
	case err := <-eout:
		return nil, err
	}
}

func (c *controllerT) doTraceroute(ctx con.Context, tms []*dm.TracerouteMeasurement) <-chan *dm.Traceroute {
	ret := make(chan *dm.Traceroute)
	log.Debug("Running traceroutes: ", tms)
	go func() {
		var checkCache = make(map[string]*dm.TracerouteMeasurement)
		var remaining []*dm.TracerouteMeasurement
		var cacheKeys []string
		for _, tm := range tms {
			if tm.CheckCache {
				key := tm.Key()
				checkCache[key] = tm
				cacheKeys = append(cacheKeys, key)
				continue
			}
			remaining = append(remaining, tm)
		}
		var found map[string]*dm.Traceroute
		if len(cacheKeys) > 0 {
			var err error
			found, err = checkTraceCache(ctx, cacheKeys, c.cache)
			if err != nil {
				log.Error(err)
			}
		}
		// Figure out what we got vs what we asked for
		for key, val := range checkCache {
			// For each one that we looked for,
			// If it was found, send it back,
			// Otherwise, add it to the remaining list
			if p, ok := found[key]; ok {
				ret <- p
			} else {
				remaining = append(remaining, val)
			}
		}
		var checkDb = make(map[string]*dm.TracerouteMeasurement)
		var checkDbArg []*dm.TracerouteMeasurement
		working := remaining
		remaining = nil
		for _, pm := range working {
			if pm.CheckDb {
				checkDb[pm.Key()] = pm
				checkDbArg = append(checkDbArg, pm)
				continue
			}
			remaining = append(remaining, pm)
		}
		dbs, err := checkTraceDb(ctx, checkDbArg, c.db)
		if err != nil {
			log.Error(err)
		}
		// Again figure out what we got out of what we asked for
		for key, val := range checkDb {
			if p, ok := dbs[key]; ok {
				//This should be stored in the cache
				go func() {
					if p.StopReason != "COMPLETED" {
						return
					}
					var err = c.cache.SetWithExpire(key, p.CMarshal(), 5*60)
					if err != nil {
						log.Info(err)
					}
				}()
				ret <- p
			} else {
				remaining = append(remaining, val)
			}
		}
		mts := make(map[router.ServiceDef][]*dm.TracerouteMeasurement)
		for _, tm := range remaining {
			ip, _ := util.Int32ToIPString(tm.Src)
			sd, err := c.router.GetService(ip)
			if err != nil {
				log.Error(err)
				ret <- &dm.Traceroute{
					Src:   tm.Src,
					Dst:   tm.Dst,
					Error: err.Error(),
				}
				continue
			}
			mts[sd] = append(mts[sd], tm)
		}
		var wg sync.WaitGroup
		for sd, tms := range mts {
			wg.Add(1)
			go func(s router.ServiceDef, meas []*dm.TracerouteMeasurement) {
				defer wg.Done()
				mt, err := c.router.GetMT(s)
				if err != nil {
					log.Error(err)
					errorAllTrace(ctx, err, ret, meas)
					return
				}
				defer mt.Close()
				pc, err := mt.Traceroute(ctx, &dm.TracerouteArg{
					Traceroutes: meas,
				})
				if err != nil {
					log.Error(err)
					errorAllTrace(ctx, err, ret, meas)
					return
				}
				for {
					select {
					case <-ctx.Done():
						return
					case pp, ok := <-pc:
						if !ok {
							return
						}
						log.Debug("Got TR ", pp)
						id, err := c.db.StoreTraceroute(pp)
						if err != nil {
							log.Error(err)
						}
						pp.Id = id
						if pp.Error == "" {
							err = c.cache.SetWithExpire(pp.Key(), pp.CMarshal(), 5*60)
							if err != nil {
								log.Error(err)
							}
						}
						select {
						case ret <- pp:
						case <-ctx.Done():
							return
						}
					}
				}
			}(sd, tms)
		}
		wg.Wait()
		close(ret)
	}()

	return ret
}

func (c *controllerT) fetchVPs(ctx con.Context, gvp *dm.VPRequest) (*dm.VPReturn, error) {
	mts := c.router.All()
	var ret dm.VPReturn
	for _, mt := range mts {
		vpc, err := mt.GetVPs(ctx, gvp)
		if err != nil {
			return nil, err
		}
		for vp := range vpc {
			ret.Vps = append(ret.Vps, vp.Vps...)
		}
		mt.Close()
	}
	return &ret, nil
}

func (c *controllerT) doGetVPs(ctx con.Context, gvp *dm.VPRequest) (*dm.VPReturn, error) {
	return c.fetchVPs(ctx, gvp)
}

func startHTTP(addr string) {
	for {
		log.Error(http.ListenAndServe(addr, nil))
	}
}

func (c *controllerT) stop() {
	if c.db != nil {
		c.db.Close()
	}
}

func (c *controllerT) run(ec chan error, con Config, db DataAccess, cache ca.Cache, r router.Router) {
	controller.config = con
	controller.db = db
	controller.cache = cache
	controller.router = r
	if db == nil {
		log.Errorf("Nil db in Controller Start")
		c.stop()
		ec <- errors.New("Controller Start, nil DB")
		return
	}
	if cache == nil {
		log.Errorf("Nil cache in Controller start")
		c.stop()
		ec <- errors.New("Controller Start, nil Cache")
		return
	}
	if r == nil {
		log.Errorf("Nil router in Controller start")
		c.stop()
		ec <- errors.New("Controller Start, nil router")
		return
	}
	log.Infof("Starting with creds: %s, %s", *con.Local.CertFile, *con.Local.KeyFile)
	certs, err := credentials.NewServerTLSFromFile(*con.Local.CertFile, *con.Local.KeyFile)
	if err != nil {
		log.Error(err)
		c.stop()
		ec <- err
		return
	}
	controller.server = grpc.NewServer(grpc.Creds(certs))
	controllerapi.RegisterControllerServer(controller.server, c)
	controller.sm = &spoofMap{
		sm: make(map[uint32]*channel),
	}
	go controller.startRPC(ec)
}

// Start starts a central controller with the given configuration
func Start(c Config, db DataAccess, cache ca.Cache, r router.Router) chan error {
	log.Info("Starting controller")
	http.Handle("/metrics", prometheus.Handler())
	mux := http.NewServeMux()
	mux.HandleFunc(v1Prefix+"vps", controller.VPSHandler)
	mux.HandleFunc(v1Prefix+"rr", controller.RecordRouteHandler)
	mux.HandleFunc(v1Prefix+"ts", controller.TimeStampHandler)
	mux.HandleFunc(v1Prefix+"pings", controller.GetPingsHandler)
	mux.HandleFunc(v1Prefix+"ping", controller.PingHandler)
	mux.HandleFunc(v1Prefix+"traceroute", controller.TracerouteHandler)
	mux.HandleFunc(v1Prefix+"traceroutes", controller.GetTracesHandler)
	go func() {
		log.Error(http.ListenAndServe(":8080", mux))
	}()
	go startHTTP(*c.Local.PProfAddr)
	errChan := make(chan error, 2)
	go controller.run(errChan, c, db, cache, r)
	return errChan
}

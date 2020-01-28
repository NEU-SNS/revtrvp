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
	"net"
	"os"
	"time"

	"golang.org/x/net/context"

	dm "github.com/NEU-SNS/revtrvp/datamodel"
	"github.com/NEU-SNS/revtrvp/log"
	plc "github.com/NEU-SNS/revtrvp/plcontroller/pb"
	"github.com/NEU-SNS/revtrvp/spoofmap"
	"github.com/NEU-SNS/revtrvp/util"
	"github.com/NEU-SNS/revtrvp/warts"
	"github.com/NEU-SNS/revtrvp/watcher"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	nameSpace     = "plcontroller"
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
	timeoutCounterByVPMT = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "rpc",
		Name:      "timeout_by_vp",
		Help:      "The count of Rpc timeouts by VP, per measurement type",
	}, []string{"vp", "measurement_type"})
	errorCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "rpc",
		Name:      "error_count",
		Help:      "Count of Rpc Errors",
	})
	errorCounterByVPMT = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: nameSpace,
		Subsystem: "rpc",
		Name:      "error_by_vp",
		Help:      "The count of Rpc Errors by VP, per measurement type",
	}, []string{"vp", "measurement_type"})
	pingGoroutineGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: nameSpace,
		Subsystem: "measurements",
		Name:      "ping_goroutines",
		Help:      "The current number of goroutines running pings",
	})
	pingResponseTimes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: nameSpace,
		Subsystem: "measurements",
		Name:      "ping_response_times",
		Help:      "The time it takes for pings to respond",
	})
	tracerouteGoroutineGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: nameSpace,
		Subsystem: "measurements",
		Name:      "traceroute_goroutines",
		Help:      "The current number of goroutines running traceroutes",
	})

	tracerouteResponseTimes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: nameSpace,
		Subsystem: "measurements",
		Name:      "traceroute_response_times",
		Help:      "The time it takes for traceroutes to respond",
	})
	ipOptionsResponseTimes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: nameSpace,
		Subsystem: "measurements",
		Name:      "options_response_times",
		Help:      "The time it takes for different ip options probes to respond",
	}, []string{"spoofed", "option"})
	vpsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: nameSpace,
		Subsystem: "vantage_points",
		Name:      "connected_vantage_points",
		Help:      "The number of currently connected vantage points",
	})
)

func init() {
	prometheus.MustRegister(errorCounterByVPMT)
	prometheus.MustRegister(timeoutCounterByVPMT)
	prometheus.MustRegister(ipOptionsResponseTimes)
	prometheus.MustRegister(procCollector)
	prometheus.MustRegister(rpcCounter)
	prometheus.MustRegister(timeoutCounter)
	prometheus.MustRegister(errorCounter)
	prometheus.MustRegister(pingGoroutineGauge)
	prometheus.MustRegister(tracerouteGoroutineGauge)
	prometheus.MustRegister(pingResponseTimes)
	prometheus.MustRegister(tracerouteResponseTimes)
	prometheus.MustRegister(vpsConnected)
}

type PlController struct {
	server   *grpc.Server
	config   Config
	db       VPStore
	w        watcher.Watcher
	client   Client
	spoofs   spoofmap.SpoofMap
	send     Sender
	ip       uint32
	shutdown chan struct{}
	ec       chan error
	started  chan struct{}
}

type options struct {
	c     Config
	db    VPStore
	cl    Client
	send  Sender
	watch watcher.Watcher
}

type ServerOption func(*options)

func WithConfig(c Config) ServerOption {
	return func(o *options) {
		o.c = c
	}
}

func WithVPStore(vps VPStore) ServerOption {
	return func(o *options) {
		o.db = vps
	}
}

func WithClient(cl Client) ServerOption {
	return func(o *options) {
		o.cl = cl
	}
}

func WithSender(s Sender) ServerOption {
	return func(o *options) {
		o.send = s
	}
}

func WithWatcher(w watcher.Watcher) ServerOption {
	return func(o *options) {
		o.watch = w
	}
}

func New(opts ...ServerOption) (*PlController, error) {
	var o options
	for _, op := range opts {
		op(&o)
	}
	if o.send == nil {
		o.send = &ControllerSender{RootCA: *o.c.Local.RootCA}
	}
	if o.cl == nil {
		return nil, fmt.Errorf("No Client Provided")
	}
	if o.db == nil {
		return nil, fmt.Errorf("No VPStore Provided")
	}
	if o.watch == nil {
		return nil, fmt.Errorf("No Watcher Provided")
	}
	var pl PlController
	pl.client = o.cl
	pl.db = o.db
	pl.send = o.send
	pl.config = o.c
	pl.w = o.watch
	ips, err := util.GetBindAddr()
	if err != nil {
		return nil, err
	}
	ip, err := util.IPStringToInt32(ips)
	if err != nil {
		return nil, err
	}
	log.Debug("Using bind addr: ", ips)
	pl.ip = ip
	pl.shutdown = make(chan struct{})
	pl.spoofs = spoofmap.New(pl.send)
	pl.started = make(chan struct{})
	return &pl, nil
}

// Start starts a plcontroller with the given configuration
func (c *PlController) Start() error {
	return c.run()
}

type loggingListener struct {
	l net.Listener
}

func (l loggingListener) Accept() (net.Conn, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	log.Infof("Accepted Conn from: %s\n", c.RemoteAddr().String())
	return c, nil
}

func (l loggingListener) Close() error {
	return l.l.Close()
}

func (l loggingListener) Addr() net.Addr {
	return l.l.Addr()
}

// When this returns the server is essentially dead, so call stop before any return
func (c *PlController) run() error {
	creds, err := credentials.NewServerTLSFromFile(*c.config.Local.CertFile, *c.config.Local.KeyFile)
	if err != nil {
		return err
	}
	c.server = grpc.NewServer(grpc.Creds(creds))
	plc.RegisterPLControllerServer(c.server, c)
	addr := fmt.Sprintf("%s:%d", *c.config.Local.Addr,
		*c.config.Local.Port)
	l, e := net.Listen("tcp", addr)
	if e != nil {
		log.Errorf("Failed to listen: %v", e)
		c.Stop()
		return e
	}
	go c.handlEvents()
	close(c.started)
	return c.server.Serve(loggingListener{l})
}

func (c *PlController) Stop() {
	<-c.started
	if c.shutdown != nil {
		close(c.shutdown)
	}
	c.removeAllVps()
	if c.spoofs != nil {
		c.spoofs.Quit()
	}
	if c.server != nil {
		c.server.Stop()
	}
	// Time to clean up
	<-time.After(time.Second * 10)
}

func (c *PlController) recSpoof(ctx context.Context, rs *dm.Spoof) (*dm.NotifyRecSpoofResponse, error) {
	resp := &dm.NotifyRecSpoofResponse{}
	dummy := &dm.PingMeasurement{
		Src:     rs.Sip,
		Dst:     rs.Dst,
		Count:   "1",
		Timeout: 2,
		Ttl:     "1",
		Sport:   "61681",
		Dport:   "62195",
	}
	src, _ := util.Int32ToIPString(rs.Sip)
	pr, id, err := c.client.DoMeasurement(src, dummy)
	go func() {
		select {
		case <-pr:
		case <-ctx.Done():
			_ = c.client.RemoveMeasurement(src, id)
		}
	}()
	if err != nil {
		log.Error(err, " ", *rs)
		return resp, err
	}
	err = c.spoofs.Register(*rs)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return resp, nil
}

func (c *PlController) runPing(ctx context.Context, pa *dm.PingMeasurement) (dm.Ping, error) {
	rpcCounter.Inc()
	timeout := pa.Timeout
	if timeout == 0 {
		timeout = *c.config.Local.Timeout
	}
	src, err := util.Int32ToIPString(pa.Src)
	if err != nil {
		errorCounterByVPMT.WithLabelValues(src, "PING").Inc()
		return dm.Ping{}, err
	}
	resp, id, err := c.client.DoMeasurement(src, pa)
	if err != nil {
		errorCounterByVPMT.WithLabelValues(src, "PING").Inc()
		return dm.Ping{}, err
	}
	select {
	case r := <-resp:
		switch t := r.Ret.(type) {
		case warts.Ping:
			return dm.ConvertPing(t), nil
		default:
			errorCounter.Inc()
			errorCounterByVPMT.WithLabelValues(src, "PING").Inc()
			return dm.Ping{}, fmt.Errorf("Wrong type in ping response")
		}
	case <-time.After(time.Second * time.Duration(timeout)):
		timeoutCounter.Inc()
		timeoutCounterByVPMT.WithLabelValues(src, "PING").Inc()
		err := c.client.RemoveMeasurement(src, id)
		if err != nil {
			log.Error(err)
		}
		return dm.Ping{}, fmt.Errorf("Ping timed out")
	case <-ctx.Done():
		err := c.client.RemoveMeasurement(src, id)
		if err != nil {
			log.Error(err)
		}
		errorCounterByVPMT.WithLabelValues(src, "PING").Inc()
		return dm.Ping{}, ctx.Err()
	}
}

func (c *PlController) acceptProbe(probe *dm.Probe) error {
	return c.spoofs.Receive(probe)
}

func (c *PlController) runTraceroute(ctx context.Context, ta *dm.TracerouteMeasurement) (dm.Traceroute, error) {
	rpcCounter.Inc()
	timeout := ta.Timeout
	if timeout == 0 {
		timeout = *c.config.Local.Timeout
	}

	src, err := util.Int32ToIPString(ta.Src)
	if err != nil {
		errorCounterByVPMT.WithLabelValues(src, "TRACEROUTE").Inc()
		return dm.Traceroute{}, err
	}
	resp, id, err := c.client.DoMeasurement(src, ta)
	if err != nil {
		errorCounterByVPMT.WithLabelValues(src, "TRACEROUTE").Inc()
		return dm.Traceroute{}, err
	}
	select {
	case r := <-resp:
		switch t := r.Ret.(type) {
		case warts.Traceroute:
			return dm.ConvertTraceroute(t), nil
		default:
			errorCounter.Inc()
			errorCounterByVPMT.WithLabelValues(src, "TRACEROUTE").Inc()
			return dm.Traceroute{}, fmt.Errorf("Wrong type in traceroute response")
		}
	case <-time.After(time.Second * time.Duration(timeout)):
		timeoutCounter.Inc()
		timeoutCounterByVPMT.WithLabelValues(src, "TRACEROUTE").Inc()
		src, _ := util.Int32ToIPString(ta.Src)
		err = c.client.RemoveMeasurement(src, id)
		if err != nil {
			log.Error(err)
		}
		return dm.Traceroute{}, fmt.Errorf("Traceroute timed out")
	case <-ctx.Done():
		err = c.client.RemoveMeasurement(src, id)
		if err != nil {
			log.Error(err)
		}
		errorCounterByVPMT.WithLabelValues(src, "TRACEROUTE").Inc()
		return dm.Traceroute{}, ctx.Err()
	}
}

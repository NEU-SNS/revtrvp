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

package router

import (
	"fmt"
	"sync"

	"golang.org/x/net/context"

	dm "github.com/NEU-SNS/revtr-vp/datamodel"
)

type service uint

const (
	// PlanetLab is the Planet lab service
	PlanetLab service = iota + 1
)

var (
	// ErrCantCreateMt is returned when an unknown measurement tool is asked for
	ErrCantCreateMt = fmt.Errorf("No measurement tool found for the service")
)

// MeasurementTool is the interface for a measurement source the controller can use
type MeasurementTool interface {
	Ping(context.Context, *dm.PingArg) (<-chan *dm.Ping, error)
	Traceroute(context.Context, *dm.TracerouteArg) (<-chan *dm.Traceroute, error)
	GetVPs(context.Context, *dm.VPRequest) (<-chan *dm.VPReturn, error)
	ReceiveSpoof(context.Context, *dm.RecSpoof) (<-chan *dm.NotifyRecSpoofResponse, error)
	Close() error
}

func (r *router) create(s ServiceDef) (MeasurementTool, error) {
	switch s.Service {
	case PlanetLab:
		return createPLMT(s, r)
	}
	return nil, ErrCantCreateMt
}

// ServiceDef is the definition of
type ServiceDef struct {
	Addr    string
	Port    string
	Service service
}

func (sd ServiceDef) key() string {
	return fmt.Sprintf("%s:%s:%v", sd.Addr, sd.Port, sd.Service)
}

type source struct{}

func (s source) Get(dst string) (ServiceDef, error) {
	return ServiceDef{
		Addr:    "plcontroller.revtr.ccs.neu.edu",
		Port:    "4380",
		Service: PlanetLab,
	}, nil
}

func (s source) All() []ServiceDef {
	return []ServiceDef{ServiceDef{
		Addr:    "plcontroller.revtr.ccs.neu.edu",
		Port:    "4380",
		Service: PlanetLab,
	}}
}

// Source is a source of service defs from src addresses
type Source interface {
	Get(string) (ServiceDef, error)
	All() []ServiceDef
}

type mtCache struct {
	mu    sync.Mutex
	cache map[string]*mtCacheItem
}

type mtCacheItem struct {
	mt       MeasurementTool
	refCount uint32
}

func (mt *mtCacheItem) String() string {
	return fmt.Sprintf("%v", *mt)
}

// Router is the interface for something that routes srcs to measurement tools
type Router interface {
	GetMT(ServiceDef) (MeasurementTool, error)
	GetService(string) (ServiceDef, error)
	All() []MeasurementTool
	SetSource(Source)
}

type router struct {
	source Source
	cache  mtCache
	caPath string
}

// New creates a new Router
func New(caPath string) Router {
	return &router{
		cache: mtCache{
			cache: make(map[string]*mtCacheItem),
		},
		source: source{},
		caPath: caPath,
	}
}

func (r *router) SetSource(s Source) {
	r.source = s
}

func (r *router) GetMT(s ServiceDef) (MeasurementTool, error) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	if mt, ok := r.cache.cache[s.key()]; ok {
		mt.refCount++
		return mt.mt, nil
	}
	mt, err := r.create(s)
	if err != nil {
		return nil, err
	}
	nc := &mtCacheItem{
		mt:       mt,
		refCount: 1,
	}
	r.cache.cache[s.key()] = nc
	return mt, nil
}

func (r *router) GetService(addr string) (ServiceDef, error) {
	return r.source.Get(addr)
}

func (r *router) All() []MeasurementTool {
	services := r.source.All()
	var ret []MeasurementTool
	for _, service := range services {
		mt, err := r.GetMT(service)
		if err != nil {
			continue
		}
		ret = append(ret, mt)
	}
	return ret
}

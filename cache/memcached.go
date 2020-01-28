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

package cache

import (
	"fmt"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ErrorNoClient is returned when there is no cache client
	ErrorNoClient = fmt.Errorf("No cache client!")
	// ErrorCacheMiss is when a cache miss occurs
	ErrorCacheMiss = memcache.ErrCacheMiss
	// ErrorNotStored is when an error occurs when storing something
	ErrorNotStored = memcache.ErrNotStored
	// ErrorServerError is when there is a server error
	ErrorServerError = memcache.ErrServerError
	// ErrorMalformedKey is a malformed key error
	ErrorMalformedKey = memcache.ErrMalformedKey
	// ErrorNoServers is when there are no servers set
	ErrorNoServers = memcache.ErrNoServers
)

var (
	cacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_hits",
		Help: "The number of cache hits.",
	})
	cacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_misses",
		Help: "The number of cache misses.",
	})
	cacheErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_errors",
		Help: "The number of cache errors.",
	})
	cacheSets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_sets",
		Help: "The number of cache sets.",
	})
	cacheGets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cache_gets",
		Help: "The number of cache gets.",
	})
)

func init() {
	prometheus.MustRegister(cacheHits)
	prometheus.MustRegister(cacheMisses)
	prometheus.MustRegister(cacheErrors)
	prometheus.MustRegister(cacheSets)
	prometheus.MustRegister(cacheGets)
}

func toError(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case memcache.ErrCacheMiss:
		return ErrorCacheMiss
	case memcache.ErrNotStored:
		return ErrorNotStored
	case memcache.ErrServerError:
		return ErrorServerError
	case memcache.ErrMalformedKey:
		return ErrorMalformedKey
	case memcache.ErrNoServers:
		return ErrorNoServers
	default:
		return err
	}

}

type outItem struct {
	data []byte
	key  string
}

func (o outItem) Key() string {
	return o.key
}

func (o outItem) Value() []byte {
	return o.data
}

func toOutItem(key string, data []byte) outItem {
	return outItem{
		data: data,
		key:  key,
	}
}

type cache struct {
	c *memcache.Client
}

// New creates a new cache
func New(servers ServerList) Cache {
	return &cache{
		c: memcache.New(servers...),
	}
}

func (c *cache) Get(key string) (Item, error) {
	if c.c == nil {
		cacheErrors.Inc()
		return nil, ErrorNoClient
	}
	cacheGets.Inc()
	item, err := c.c.Get(key)
	if err != nil {
		if err == memcache.ErrCacheMiss {
			cacheMisses.Inc()
		} else {
			cacheErrors.Inc()
		}
		return nil, toError(err)
	}
	cacheHits.Inc()
	return toOutItem(item.Key, item.Value), nil
}

func (c *cache) GetMulti(keys []string) (map[string]Item, error) {
	if c.c == nil {
		cacheErrors.Inc()
		return nil, ErrorNoClient
	}
	cacheGets.Add(float64(len(keys)))
	nkeys := len(keys)
	ukeys := make([]string, nkeys)
	for i, key := range keys {
		ukeys[i] = key
	}
	multi, err := c.c.GetMulti(ukeys)
	if err != nil {
		cacheErrors.Inc()
		return nil, toError(err)
	}
	ret := make(map[string]Item)
	for k, v := range multi {
		cacheHits.Inc()
		ret[k] = toOutItem(v.Key, v.Value)
	}
	cacheMisses.Add(float64(len(keys) - len(ret)))
	return ret, nil
}

func (c *cache) Set(key string, val []byte) error {
	if c.c == nil {
		cacheErrors.Inc()
		return ErrorNoClient
	}
	// Default to 15 minute expire. This is set
	// based on the old system, may need to be
	// updated in the future
	err := c.SetWithExpire(key, val, 15*60)
	if err != nil {
		cacheErrors.Inc()
	}
	return toError(err)
}

func (c *cache) SetWithExpire(key string, val []byte, exp int32) error {
	if c.c == nil {
		cacheErrors.Inc()
		return ErrorNoClient
	}
	cacheSets.Inc()
	err := c.c.Set(&memcache.Item{
		Key:        key,
		Value:      val,
		Expiration: exp,
	})
	if err != nil {
		cacheErrors.Inc()
	}
	return toError(err)
}

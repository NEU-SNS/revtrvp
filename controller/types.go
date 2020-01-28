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
	"github.com/NEU-SNS/revtr-vp/cache"
	da "github.com/NEU-SNS/revtr-vp/dataaccess"
)

// Config is the config struct for the controller
type Config struct {
	Local LocalConfig
	Db    da.DbConfig
	Cache cache.Config
}

// LocalConfig is the configuration options for the controller
type LocalConfig struct {
	Addr         *string `flag:"a"`
	Port         *int    `flag:"p"`
	CloseStdDesc *bool   `flag:"D"`
	PProfAddr    *string `flag:"pprof"`
	AutoConnect  *bool   `flag:"auto-connect"`
	CertFile     *string `flag:"cert-file"`
	KeyFile      *string `flag:"key-file"`
	ConnTimeout  *int64  `flag:"conn-timeout"`
	RootCA       *string `flag:"root-ca"`
}

// NewConfig returns a new blank Config
func NewConfig() Config {
	lc := LocalConfig{
		Addr:         new(string),
		CloseStdDesc: new(bool),
		PProfAddr:    new(string),
		AutoConnect:  new(bool),
		CertFile:     new(string),
		KeyFile:      new(string),
		ConnTimeout:  new(int64),
		Port:         new(int),
		RootCA:       new(string),
	}
	c := Config{
		Local: lc,
		Db:    da.DbConfig{},
		Cache: cache.NewConfig(),
	}
	return c
}

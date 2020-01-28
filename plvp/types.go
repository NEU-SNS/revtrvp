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

// Flags represents the arguments to the vantage-point
type Flags struct {
	Local   LocalConfig
	Scamper ScamperConfig
}

// Config represents the configuration of the vantage-point
type Config struct {
	Local   LocalConfig
	Scamper ScamperConfig
}

// LocalConfig represents the configuration of the vantage-point minus Scamper
type LocalConfig struct {
	Addr         *string `flag:"a"`
	CloseStdDesc *bool   `flag:"d"`
	Port         *int    `flag:"p"`
	PProfAddr    *string `flag:"pprof-addr"`
	AutoConnect  *bool   `flag:"auto-connect"`
	SecureConn   *bool   `flag:"secure-conn"`
	CertPath     *string `flag:"cert-path"`
	KeyPath      *string `flag:"key-path"`
	StartScamp   *bool   `flag:"start-scamper"`
	Host         *string `flag:"host"`
	RootCA       *string `flag:"root-ca"`
}

// ScamperConfig represents the scamper configuration options
type ScamperConfig struct {
	BinPath *string `flag:"b"`
	Host    *string `flag:"scamper-host"`
	Port    *string `flag:"scamper-port"`
}

// NewConfig creates a new config struct for the plvp
func NewConfig() Config {
	lc := LocalConfig{
		Addr:         new(string),
		AutoConnect:  new(bool),
		CloseStdDesc: new(bool),
		PProfAddr:    new(string),
		SecureConn:   new(bool),
		CertPath:     new(string),
		KeyPath:      new(string),
		StartScamp:   new(bool),
		Host:         new(string),
		Port:         new(int),
		RootCA:       new(string),
	}
	sc := ScamperConfig{
		Port:    new(string),
		Host:    new(string),
		BinPath: new(string),
	}
	return Config{
		Local:   lc,
		Scamper: sc,
	}
}

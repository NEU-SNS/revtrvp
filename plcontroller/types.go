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

package plcontroller

import (
	"github.com/NEU-SNS/revtr-vp/datamodel"
	"github.com/NEU-SNS/revtr-vp/scamper"
)

// Config is the config struct for the plc
type Config struct {
	Local   LocalConfig
	Scamper ScamperConfig
	Db      DbConfig
}

// LocalConfig is the local section of the config
type LocalConfig struct {
	Addr         *string `flag:"a"`
	Port         *int    `flag:"p"`
	CloseStdDesc *bool   `flag:"D"`
	PProfAddr    *string `flag:"pprof"`
	Timeout      *int64  `flag:"t"`
	CertFile     *string `flag:"cert-file"`
	KeyFile      *string `flag:"key-file"`
	SSHKeyPath   *string `flag:"sshkey-path"`
	PLUName      *string `flag:"pluname"`
	UpdateURL    *string `flag:"update-url"`
	RootCA       *string `flag:"root-ca"`
}

// ScamperConfig is the scamper config info
type ScamperConfig struct {
	Port          *string `flag:"scamper-port"`
	SockDir       *string `flag:"socket-dir"`
	BinPath       *string `flag:"scamper-bin"`
	ConverterPath *string `flag:"converter-path"`
}

// DbConfig is the DB config options
type DbConfig struct {
	UName    *string `flag:"db-uname"`
	Password *string `flag:"db-pass"`
	Host     *string `flag:"db-host"`
	Port     *string `flag:"db-port"`
	Db       *string `flag:"db-name"`
}

// NewConfig creates a new config
func NewConfig() Config {
	lc := LocalConfig{
		Addr:         new(string),
		Port:         new(int),
		CloseStdDesc: new(bool),
		PProfAddr:    new(string),
		Timeout:      new(int64),
		CertFile:     new(string),
		KeyFile:      new(string),
		SSHKeyPath:   new(string),
		PLUName:      new(string),
		UpdateURL:    new(string),
		RootCA:       new(string),
	}
	sc := ScamperConfig{
		Port:          new(string),
		SockDir:       new(string),
		BinPath:       new(string),
		ConverterPath: new(string),
	}
	return Config{
		Local:   lc,
		Scamper: sc,
		Db: DbConfig{
			UName:    new(string),
			Password: new(string),
			Host:     new(string),
			Port:     new(string),
			Db:       new(string),
		},
	}
}

type Sender interface {
	Send([]*datamodel.Probe, uint32) error
	Close() error
}

// Client is the measurment client interface
type Client interface {
	AddSocket(*scamper.Socket)
	RemoveSocket(string)
	GetSocket(string) (*scamper.Socket, error)
	RemoveMeasurement(string, uint32) error
	DoMeasurement(string, interface{}) (<-chan scamper.Response, uint32, error)
	GetAllSockets() <-chan *scamper.Socket
}

// VPStore is the interface for the vpstore needed by the plc
type VPStore interface {
	ClearAllVPs() error
	UpdateController(uint32, uint32, uint32) error
	GetVPs() ([]*datamodel.VantagePoint, error)
	GetActiveVPs() ([]*datamodel.VantagePoint, error)
	UpdateCheckStatus(uint32, string) error
	Close() error
}

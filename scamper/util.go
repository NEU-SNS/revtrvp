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

// Package scamper is a library to work with scamper control sockets
package scamper

import (
	"fmt"
	"os"
	"strconv"

	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/mproc/proc"
	"github.com/NEU-SNS/revtrvp/util"
)

// Options for the scamper process
const (
	// IPv4 Mode
	IPv4 = "-4"
	// IPv6 Mode
	IPv6 = "-6"
	// PORT to use
	PORT = "-P"
	// SOCKETDIR The Socket directory
	SOCKETDIR = "-U"
	// REMOTE Flag
	REMOTE = "-R"
	// SUDO the cmd must be run with sudo
	SUDO = "sudo"
	// ADDRINDEX is the index of the addr arg
	ADDRINDEX = 2
	// PPS is the packet per second rate of the scamper process
	PPS = "-p"
	// Private key of the server
	CAFILE = "cafile"
)

// Config is the configuration options for the scamper process
type Config struct {
	Port         string
	Path         string
	ScPath       string
	IP           string
	ScParserPath string
	Rate         string
	CAFile       string
}

// ParseConfig checks the given confiuration options to ensure validity
func ParseConfig(sc Config) error {
	val, err := strconv.Atoi(sc.Port)
	if err != nil {
		return err
	}
	if val < 1 || val > 65535 {
		return util.ErrorInvalidPort
	}
	if sc.Path != "" {
		err = checkScamperSockDir(sc.Path)
		if err != nil {
			return err
		}
	}

	if sc.CAFile == "" {
		return util.ErrorInvalidCAFile
	}

	return checkBinPath(sc.ScPath)
}

func checkBinPath(binPath string) error {
	fi, err := os.Stat(binPath)
	if err != nil {
		if os.IsNotExist(err) {

			return fmt.Errorf("scamper path does not exist: %s", binPath)
		}
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("scamper path is not an executable: %s", binPath)
	}
	return nil
}

func makeScamperDir(sockDir string) error {
	return util.MakeDir(sockDir, os.ModeDir|0700)
}

func checkScamperSockDir(sockDir string) error {
	isd, err := util.IsDir(sockDir)
	if err != nil {
		if os.IsNotExist(err) {
			return makeScamperDir(sockDir)
		}
		return err
	}
	if isd {
		return nil

	}
	return fmt.Errorf("Socket directory path: %s is not a directory",
		sockDir)
}

// GetProc returns a process which will run scamper
func GetProc(sockDir, scampPort, scamperPath string) *proc.Process {

	err := checkScamperSockDir(sockDir)
	if err != nil {
		log.Errorf("Error with scamper socket directory: %v", err)
		return nil
	}
	return proc.New(scamperPath, nil,
		IPv4, "-O", "tka", PORT, scampPort, SOCKETDIR, sockDir)
}

// GetVPProc returns a process which is suitable to run on a planet-lab VP
func GetVPProc(scpath, host, port, rate, caFile string) *proc.Process {
	faddr := fmt.Sprintf("%s:%s", host, port)
	return proc.New(scpath, nil, "-O", CAFILE+"="+caFile, REMOTE, faddr, PPS, rate)
}

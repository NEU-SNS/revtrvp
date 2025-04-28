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

// Package util contains utilities uses throughout the packages
package util

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/NEU-SNS/revtrvp/log"
)

const (
	// IP is the index for the ip in a split of an address string
	IP = 0
	// PORT is the index for the port in a split of an address string
	PORT = 1
)

var (
	// ErrorInvalidIP is the error if the IP is invalid
	ErrorInvalidIP = errors.New("invalid IP address")
	// ErrorInvalidPort is the error if the Port is invalid
	ErrorInvalidPort   = errors.New("invalid port")
	ErrorInvalidCAFile = errors.New("invalid ca file")
)

// IsDir checks if what is at path dir is a directory
func IsDir(dir string) (bool, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	return fi.IsDir(), nil
}

// MakeDir create a directory at path path with permissions mode
func MakeDir(path string, mode os.FileMode) error {
	return os.Mkdir(path, mode)
}

// ParseAddrArg checks if the address in ip:port notation is valid
func ParseAddrArg(addr string) (int, net.IP, error) {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, nil, err
	}
	//shortcut, maybe resolve?
	if ip == "localhost" {
		ip = "127.0.0.1"
	}
	pport, err := strconv.Atoi(port)
	if err != nil {
		log.Errorf("Failed to parse port")
		return 0, nil, err
	}
	if pport < 1 || pport > 65535 {
		log.Errorf("Invalid port passed to Start: %d", pport)
		return 0, nil, ErrorInvalidPort
	}
	var pip net.IP
	var cont bool
	if ip == "" {
		pip = nil
		cont = true
	} else {
		pip = net.ParseIP(ip)
	}
	if pip == nil && !cont {
		log.Errorf("Invalid IP passed to Start: %s", ip)
		return 0, nil, ErrorInvalidIP
	}
	return pport, pip, nil
}

// CloseStdFiles closes the standard file descriptors
func CloseStdFiles(c bool) {
	if !c {
		return
	}
	log.Info("Closing standard file descripters")
	err := os.Stdin.Close()

	if err != nil {
		log.Error("Failed to close Stdin")
		os.Exit(1)
	}
	err = os.Stderr.Close()
	if err != nil {
		log.Error("Failed to close Stderr")
		os.Exit(1)
	}
	err = os.Stdout.Close()
	if err != nil {
		log.Error("Failed to close Stdout")
		os.Exit(1)
	}
}

// ConnToRW converts a net.Conn to a bufio.ReadWriter
func ConnToRW(c net.Conn) *bufio.ReadWriter {
	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
	rw := bufio.NewReadWriter(r, w)
	return rw
}

// ConvertBytes converts an input byte slice to an output byte slice using the
// executable at path
func ConvertBytes(path string, b []byte) ([]byte, error) {
	cmd := exec.Command(path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	_, err = stdin.Write(b)
	if err != nil {
		return nil, err
	}
	err = stdin.Close()
	if err != nil {
		return nil, err
	}
	res := make([]byte, 100*1024)
	n, err := stdout.Read(res)
	if err != nil {
		return res, err
	}
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	return res[:n], err
}

// Int32ToIPString converts an ip as an uint32 to a string
func Int32ToIPString(ip uint32) (string, error) {
	var a, b, c, d byte
	if ip < 0 || ip > 4294967295 {
		return "", fmt.Errorf("Ip out of range")
	}
	d = byte(ip & 0x000000ff)
	c = byte(ip & 0x0000ff00 >> 8)
	b = byte(ip & 0x00ff0000 >> 16)
	a = byte(ip & 0xff000000 >> 24)
	nip := net.IPv4(a, b, c, d)
	if nip == nil {
		return "", fmt.Errorf("Invalid IP")
	}
	return nip.String(), nil
}

// IPStringToInt32 converts an IP string to a uint32
func IPStringToInt32(ips string) (uint32, error) {
	ip := net.ParseIP(ips)
	if ip == nil {
		return 0, fmt.Errorf("Nil ip in IpToInt32")
	}
	ip = ip.To4()
	var res uint32
	res |= uint32(ip[0]) << 24
	res |= uint32(ip[1]) << 16
	res |= uint32(ip[2]) << 8
	res |= uint32(ip[3])
	return res, nil
}

// IPtoInt32 converts a net.IP to an uint32
func IPtoInt32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	var res uint32
	res |= uint32(ip[0]) << 24
	res |= uint32(ip[1]) << 16
	res |= uint32(ip[2]) << 8
	res |= uint32(ip[3])
	return res, nil
}

// Int32ToIP converts an uint32 into a net.IP
func Int32ToIP(ip uint32) net.IP {
	var a, b, c, d byte
	a = byte(ip)
	b = byte(ip >> 8)
	c = byte(ip >> 16)
	d = byte(ip >> 24)
	return net.IPv4(a, b, c, d)
}

// MicroToNanoSec convers microseconds to nanoseconds
func MicroToNanoSec(usec int64) int64 {
	return usec * 1000
}

// GetBindAddr gets the IP of the eth0 like address
// (!!MLab specific!!: use net1 because eth0 is private)
func GetBindAddr(netInterface string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {

		if strings.Contains(iface.Name, netInterface) &&
			// if strings.Contains(iface.Name, "net1") &&
			// if strings.Contains(iface.Name, "en7") &&
			uint(iface.Flags)&uint(net.FlagUp) > 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return "", err
			}
			for _, addr := range addrs {
				// addr := addrs[0]
				addressType := checkIPAddressType(addr.String())
				if addressType != IPv4AddressType {
					continue
				}
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					return "", err
				}
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("Didn't find %s interface", netInterface)
}

type AddressType string

const (
	IPv4AddressType    AddressType = "IPv4"
	IPv6AddressType    AddressType = "IPv6"
	InvalidAddressType AddressType = "Invalid"
)

func checkIPAddressType(addr string) AddressType {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		fmt.Printf("Invalid IP Address: %s\n", ip)
		return InvalidAddressType
	}
	for i := 0; i < len(addr); i++ {
		switch addr[i] {
		case '.':
			fmt.Printf("Given IP Address %s is IPV4 type\n", ip)
			return IPv4AddressType
		case ':':
			fmt.Printf("Given IP Address %s is IPV6 type\n", ip)
			return IPv6AddressType
		}
	}
	return InvalidAddressType
}

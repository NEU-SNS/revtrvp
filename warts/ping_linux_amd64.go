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

package warts

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"syscall"
)

const (
	icmp   = 1
	icmpv6 = 58
	tcp    = 6
	udp    = 17
)

// Ping is a warts ping
type Ping struct {
	Flags       PingFlags
	PLength     uint16
	ReplyCount  uint16
	PingReplies []PingReplyFlags
	Version     string
	Type        string
}

func (p Ping) String() string {
	return fmt.Sprintf("Ping: %s\n Replies: %d %s", p.Flags, p.ReplyCount, p.PingReplies)
}

// PingStats are warts ping stats
type PingStats struct {
	Replies uint16
	Loss    uint16
	Min     float32
	Max     float32
	Avg     float32
	StdDev  float32
}

// GetStats calculates the stats for a ping
func (p Ping) GetStats() PingStats {
	var min, max syscall.Timeval
	ret := PingStats{}
	ret.Replies = p.ReplyCount
	dups := 0
	var sum int64
	for i, rep := range p.PingReplies {
		if i == 0 {
			min = rep.RTT
			max = rep.RTT
		}
		sum += ((int64(rep.RTT.Sec) * 1000000) + int64(rep.RTT.Usec))
		switch timevalComp(min, rep.RTT) {
		case 1:
			min = rep.RTT
		}
		switch timevalComp(max, rep.RTT) {
		case -1:
			max = rep.RTT
		}
		if uint16(i) >= p.Flags.PingsSent {
			dups++
		}
	}
	if dups == 0 {
		ret.Loss = p.Flags.PingsSent - p.ReplyCount
	} else {
		ret.Loss = 0
	}
	var d, stdsum float64
	len64 := float64(len(p.PingReplies))
	if len(p.PingReplies) > 0 {
		ret.Avg = float32(sum) / float32(len64) / 1000
		d = float64(ret.Avg * 1000)
		for _, rep := range p.PingReplies {
			rtt := float64((rep.RTT.Sec * 1000000) + rep.RTT.Usec)
			diff := rtt - d
			stdsum += math.Pow(diff, 2)
		}
		us := math.Sqrt(stdsum / len64)
		ret.StdDev = float32(us) / 1000
	}

	musec := (max.Sec * 1000000) + max.Usec
	minusec := (min.Sec * 1000000) + min.Usec
	ret.Max = float32(musec) / 1000
	ret.Min = float32(minusec) / 1000
	return ret
}

func timevalComp(l, r syscall.Timeval) int {
	lsec := l.Sec
	rsec := r.Sec
	lusec := l.Usec
	rusec := r.Usec
	if lsec < rsec {
		return -1
	}
	if lsec > rsec {
		return 1
	}
	if lusec < rusec {
		return -1
	}
	if lusec > rusec {
		return 1
	}
	return 0
}

func (pf PingFlags) String() string {
	return fmt.Sprintf(
		"\nListId: %d  CycleId: %d\n"+
			"Start Time: %v\n"+
			"Probe Count: %v\n"+
			"Probe Size: %d\n"+
			"Probe Wait: %d\n"+
			"Probe TTL: %d\n"+
			"Reply Count: %d\n"+
			"Pings Sent: %d\n"+
			"Ping Method: %s\n"+
			"Source Port: %d\n"+
			"Dest. Port: %d\n"+
			"UserID: %d\n"+
			"Src: %s\n"+
			"Dst %s\n"+
			"TS: %d\n"+
			"ICMP Checksum: %d\n"+
			"MTU: %d\n"+
			"Probe Timeout: %d\n"+
			"Probe Wait (sec): %d\n",
		pf.ListID,
		pf.CycleID,
		pf.StartTime,
		pf.ProbeCount,
		pf.ProbeSize,
		pf.ProbeWait,
		pf.ProbeTTL,
		pf.ReplyCount,
		pf.PingsSent,
		pf.PingMethod,
		pf.ProbeSrcPort,
		pf.ProbeDstPort,
		pf.UserID,
		pf.Src,
		pf.Dst,
		pf.TS,
		pf.ICMPChecksum,
		pf.MTU,
		pf.ProbeTimeout,
		pf.ProbeWaitS,
	)
}

// PingMethod is the method type of the ping
type PingMethod uint8

func (pm PingMethod) String() string {
	methods := []string{
		"icmp-echo",
		"tcp-ack",
		"tcp-ack-sport",
		"udp",
		"udp-dport",
		"icmp-time",
		"tcp-syn",
	}
	return methods[pm]
}

// PingFlags are the flags set in the ping
type PingFlags struct {
	ListID       uint32
	CycleID      uint32
	SrcID        uint32
	DstID        uint32
	StartTime    syscall.Timeval
	StopReason   uint8
	StopData     uint8
	DataLength   uint16
	Data         []byte
	ProbeCount   uint16
	ProbeSize    uint16
	ProbeWaitS   uint8
	ProbeTTL     uint8
	ReplyCount   uint16
	PingsSent    uint16
	PingMethod   PingMethod
	ProbeSrcPort uint16
	ProbeDstPort uint16
	UserID       uint32
	Src          Address
	Dst          Address
	ProbeTOS     uint8
	TS           []Address
	ICMPChecksum uint16
	MTU          uint16
	ProbeTimeout uint8
	ProbeWait    uint32
	PingFlags    PFlags
	PF           PingFlag
}

// PingFlag is a flag set in a ping
type PingFlag uint8

// PFlags is a slice of PingFlags
type PFlags []PingFlag

// Strings returns a string representation of a pingflag
func (pf PingFlag) Strings() []string {
	flags := []string{
		"v4rr",
		"spoof",
		"payload",
		"tsonly",
		"tsandaddr",
		"icmpsum",
		"dl",
		"8",
	}
	var ret []string
	as8 := uint8(pf)
	for i := uint8(0); i < 8; i++ {
		if as8&(0x1<<i) != 0 {
			ret = append(ret, flags[i])
		}
	}
	return ret
}

// PingReplyFlags are the flags for a ping reply
type PingReplyFlags struct {
	DstID       uint32
	Flags       uint8
	ReplyTTL    uint8
	ReplySize   uint16
	ICMP        uint16
	RTT         syscall.Timeval
	ProbeID     uint16
	ReplyIPID   uint16
	ProbeIPID   uint16
	ReplyProto  RProto
	TCPFlags    uint8
	Addr        Address
	V4RR        V4RR
	V4TS        V4TS
	ReplyIPID32 uint32
	Tx          syscall.Timeval
	TSReply     TSReply
	ReplyFlags  PRFlags
}

// IsTsOnly returns true if the ping is tsonly ts option
func (p Ping) IsTsOnly() bool {
	return p.Flags.PF&(0x01<<3) > 0
}

// IsTsAndAddr returns true of the ping is tsandaddr
func (p Ping) IsTsAndAddr() bool {
	return len(p.Flags.TS) > 0
}

// RProto is the proto of the reply
type RProto uint8

func (rp RProto) String() string {

	switch rp {
	case icmp, icmpv6:
		return "icmp"
	case tcp:
		return "tcp"
	case udp:
		return "udp"
	default:
		return "icmp"
	}
}

// ReplyFlag is a flag in the reply
type ReplyFlag uint8

// PRFlags is an array of ReplyFlags
type PRFlags []ReplyFlag

func (prf PingReplyFlags) String() string {
	return fmt.Sprintf(
		"\n"+
			"TTL: %d\n"+
			"Reply Size: %d\n"+
			"ProbeID: %d\n"+
			"ReplyIPID: %#x\n"+
			"ProbeIPID: %#x\n"+
			"ReplyProto: %s\n"+
			"ICMP Type: %d\n"+
			"Address: %s\n"+
			"RR: %s\n"+
			"TS: %s\n"+
			"Reply IpId: %d\n"+
			"Tx: %v\n"+
			"TS Reply: %s\n"+
			"RTT: %v\n",
		prf.ReplyTTL,
		prf.ReplySize,
		prf.ProbeID,
		prf.ReplyIPID,
		prf.ProbeIPID,
		prf.ReplyProto,
		prf.ICMP,
		prf.Addr,
		prf.V4RR,
		prf.V4TS,
		prf.ReplyIPID,
		prf.Tx,
		prf.TSReply,
		prf.RTT,
	)
}

// V4RR is the RR option
type V4RR struct {
	Addrs []Address
}

// Strings stringifies a V4RR
func (v V4RR) Strings() []string {
	var ret []string
	for _, addr := range v.Addrs {
		ret = append(ret, addr.String())
	}
	return ret
}

func (v V4RR) String() string {
	return fmt.Sprintf("%v", v.Addrs)
}

// V4TS is a timestamp option
type V4TS struct {
	Addrs      []Address
	TimeStamps []uint32
}

func (v V4TS) String() string {
	var buf bytes.Buffer
	if len(v.Addrs) == 0 && len(v.TimeStamps) == 0 {
		return ""
	}
	if len(v.Addrs) == 0 {
		for _, ts := range v.TimeStamps {
			fmt.Fprintf(&buf, "TimeStamp: %v\n", ts)
		}
		return buf.String()
	}
	for i, addr := range v.Addrs {
		fmt.Fprintf(&buf, "{ Addr: %s, TimeStamp: %v }\n", addr, v.TimeStamps[i])
	}
	return buf.String()
}

// TSReply is the reply to a timestamp probe
type TSReply struct {
	OTimestamp uint32
	RTimestamp uint32
	TTimestamp uint32
}

func (tsr TSReply) String() string {
	return fmt.Sprintf("{ OTimestamp: %v, RTimestamp: %v, TTimestamp: %v}",
		tsr.OTimestamp,
		tsr.RTimestamp,
		tsr.TTimestamp)
}

func readPing(f io.Reader) (Ping, error) {
	var ping Ping
	addrs := NewAddressRefs()
	//TODO Fix Timeout in case when its not set it should be equal to the waitS
	flags, err := readPingFlags(f, addrs)
	if err != nil {
		return ping, err
	}
	ping.Flags = flags
	rc, err := readUint16(f)
	if err != nil {
		return ping, err
	}
	ping.ReplyCount = rc
	replies, err := readPingReplies(f, rc, addrs)
	if err != nil {
		return ping, err
	}
	ping.PingReplies = replies
	ping.Version = "0.4"
	ping.Type = "ping"
	return ping, nil
}

func readPingReplies(f io.Reader, count uint16, addrs *AddressRefs) ([]PingReplyFlags, error) {
	ret := make([]PingReplyFlags, count)
	for i := uint16(0); i < count; i++ {
		prf, err := readPingReplyFlags(f, addrs)
		if err != nil {
			return nil, err
		}
		ret[i] = prf
	}
	return ret, nil
}

func readPingReplyFlags(f io.Reader, addrs *AddressRefs) (PingReplyFlags, error) {
	pr := PingReplyFlags{}
	first, err := readBytes(f, 1)
	if err != nil {
		return pr, err
	}
	flags, err := getFlags(f, first[0])
	if err != nil {
		return pr, err
	}
	if len(flags) != 0 {
		_, err := readUint16(f)
		if err != nil {
			return pr, err
		}
	}
	rflags := make(PRFlags, 0)
	for _, flag := range flags {
		rflags = append(rflags, ReplyFlag(flag))
		switch flag {
		case 1:
			pr.DstID, err = readUint32(f)
			if err != nil {
				return pr, err
			}
		case 2:
			pr.Flags, err = readUint8(f)
			if err != nil {
				return pr, err
			}
		case 3:
			pr.ReplyTTL, err = readUint8(f)
			if err != nil {
				return pr, err
			}
		case 4:
			pr.ReplySize, err = readUint16(f)
			if err != nil {
				return pr, err
			}
		case 5:
			pr.ICMP, err = readUint16(f)
			if err != nil {
				return pr, err
			}
		case 6:
			val, err := readUint32(f)
			if err != nil {
				return pr, err
			}
			convertTimeval(&pr.RTT, val)
		case 7:
			pr.ProbeID, err = readUint16(f)
			if err != nil {
				return pr, err
			}
		case 8:
			pr.ReplyIPID, err = readUint16(f)
			if err != nil {
				return pr, err
			}
		case 9:
			pr.ProbeIPID, err = readUint16(f)
			if err != nil {
				return pr, err
			}
		case 10:
			ret, err := readUint8(f)
			if err != nil {
				return pr, err
			}
			pr.ReplyProto = RProto(ret)
		case 11:
			pr.TCPFlags, err = readUint8(f)
			if err != nil {
				return pr, err
			}
		case 12:
			id, err := readAddress(f, addrs)
			pr.Addr = id
			if err != nil {
				return pr, err
			}
		case 13:
			pr.V4RR, err = readV4RR(f, addrs)
			if err != nil {
				return pr, err
			}
		case 14:
			pr.V4TS, err = readV4TS(f, addrs)
			if err != nil {
				return pr, err
			}
		case 15:
			pr.ReplyIPID32, err = readUint32(f)
			if err != nil {
				return pr, err
			}
		case 16:
			pr.Tx, err = readTimeVal(f)
			if err != nil {
				return pr, err
			}
		case 17:
			pr.TSReply, err = readTSReply(f)
			if err != nil {
				return pr, err
			}
		default:
			return pr, fmt.Errorf("Invalid flag in ping reply")
		}
	}

	pr.ReplyFlags = rflags
	return pr, nil
}

func readTSReply(f io.Reader) (TSReply, error) {
	tsr := TSReply{}
	var err error
	tsr.OTimestamp, err = readUint32(f)
	if err != nil {
		return tsr, err
	}
	tsr.RTimestamp, err = readUint32(f)
	if err != nil {
		return tsr, err
	}
	tsr.TTimestamp, err = readUint32(f)
	if err != nil {
		return tsr, err
	}
	return tsr, nil
}

func readV4TS(f io.Reader, addrs *AddressRefs) (V4TS, error) {
	ts := V4TS{}
	tsc, err := readUint8(f)
	if err != nil {
		return ts, err
	}
	ipc, err := readUint8(f)
	if err != nil {
		return ts, err
	}
	ts.Addrs = make([]Address, ipc)
	ts.TimeStamps = make([]uint32, tsc)
	for i := uint8(0); i < tsc; i++ {
		addr, err := readUint32(f)
		if err != nil {
			return ts, err
		}
		ts.TimeStamps[i] = uint32(addr)
	}
	for i := uint8(0); i < ipc; i++ {
		addr, err := readAddress(f, addrs)
		if err != nil {
			return ts, err
		}
		ts.Addrs[i] = addr
	}
	return ts, nil
}

func readV4RR(f io.Reader, addrs *AddressRefs) (V4RR, error) {
	rr := V4RR{}
	count, err := readUint8(f)
	if err != nil {
		return rr, err
	}
	rr.Addrs = make([]Address, count)
	for i := uint8(0); i < count; i++ {
		addr, err := readAddress(f, addrs)
		if err != nil {
			return rr, err
		}
		rr.Addrs[i] = addr
	}
	return rr, nil
}

func readPingFlags(f io.Reader, addrs *AddressRefs) (PingFlags, error) {
	first := make([]byte, 1)
	pf := PingFlags{}
	n, err := f.Read(first)
	if err != nil {
		return pf, err
	}
	if n != 1 {
		return pf, fmt.Errorf("Failed to read, readPingFlags")
	}
	flags, err := getFlags(f, uint8(first[0]))
	if err != nil {
		return pf, err
	}
	if len(flags) != 0 {
		_, err := readUint16(f)
		if err != nil {
			return pf, err
		}
	}
	pflags := make(PFlags, 0)
	for _, flag := range flags {
		pflags = append(pflags, PingFlag(flag))
		switch flag {
		case 1:
			pf.ListID, err = readUint32(f)
			if err != nil {
				return pf, err
			}
		case 2:
			pf.CycleID, err = readUint32(f)
			if err != nil {
				return pf, err
			}
		case 3:
			pf.SrcID, err = readUint32(f)
			if err != nil {
				return pf, err
			}
		case 4:
			pf.DstID, err = readUint32(f)
			if err != nil {
				return pf, err
			}
		case 5:
			pf.StartTime, err = readTimeVal(f)
			if err != nil {
				return pf, err
			}
		case 6:
			pf.StopReason, err = readUint8(f)
			if err != nil {
				return pf, err
			}
		case 7:
			pf.StopData, err = readUint8(f)
			if err != nil {
				return pf, err
			}
		case 8:
			pf.DataLength, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 9:
			pf.Data, err = readBytes(f, int(pf.DataLength))
			if err != nil {
				return pf, err
			}
		case 10:
			pf.ProbeCount, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 11:
			pf.ProbeSize, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 12:
			pf.ProbeWaitS, err = readUint8(f)
			if err != nil {
				return pf, err
			}
		case 13:
			pf.ProbeTTL, err = readUint8(f)
			if err != nil {
				return pf, err
			}
		case 14:
			pf.ReplyCount, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 15:
			pf.PingsSent, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 16:
			res, err := readUint8(f)
			if err != nil {
				return pf, err
			}
			pf.PingMethod = PingMethod(res)
		case 17:
			pf.ProbeSrcPort, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 18:
			pf.ProbeDstPort, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 19:
			pf.UserID, err = readUint32(f)
			if err != nil {
				return pf, err
			}
		case 20:
			addr, err := readAddress(f, addrs)
			if err != nil {
				return pf, err
			}
			pf.Src = addr
		case 21:
			addr, err := readAddress(f, addrs)
			if err != nil {
				return pf, err
			}
			pf.Dst = addr
		case 22:
			ret, err := readUint8(f)
			if err != nil {
				return pf, err
			}
			pf.PF = PingFlag(ret)
		case 23:
			pf.ProbeTOS, err = readUint8(f)
			if err != nil {
				return pf, err
			}
		case 24:
			num, err := readUint8(f)
			if err != nil {
				return pf, err
			}
			pf.TS = make([]Address, num)
			for i := uint8(0); i < num; i++ {
				addr, err := readAddress(f, addrs)
				if err != nil {
					return pf, err
				}
				pf.TS = append(pf.TS, addr)
			}
		case 25:
			pf.ICMPChecksum, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 26:
			pf.MTU, err = readUint16(f)
			if err != nil {
				return pf, err
			}
		case 27:
			pf.ProbeTimeout, err = readUint8(f)
			if err != nil {
				return pf, err
			}
		case 28:
			pf.ProbeWait, err = readUint32(f)
			if err != nil {
				return pf, err
			}
		default:
			return pf, fmt.Errorf("Parsed a flag that shouldn't be there: readPingFlags")
		}
	}
	pf.PingFlags = pflags
	return pf, nil
}

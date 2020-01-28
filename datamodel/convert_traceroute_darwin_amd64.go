// +build !386

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

package datamodel

import (
	"time"

	"github.com/NEU-SNS/revtrvp/warts"
)

// ConvertTraceroute converts a warts Traceroute to a datamodel Traceroute
func ConvertTraceroute(in warts.Traceroute) Traceroute {
	t := Traceroute{}
	t.Type = "trace"
	t.UserId = in.Flags.UserID
	t.Src = uint32(in.Flags.Src.Address)
	t.Dst = uint32(in.Flags.Dst.Address)
	t.Method = in.Flags.TraceType.String()
	t.Sport = uint32(in.Flags.SourcePort)
	t.Dport = uint32(in.Flags.DestPort)
	t.StopReason = in.Flags.StopReason.String()
	t.StopData = uint32(in.Flags.StopData)
	tt := TracerouteTime{}
	tt.Sec = in.Flags.StartTime.Sec
	tt.Usec = int64(in.Flags.StartTime.Usec)
	tt.Ftime = time.Unix(tt.Sec, tt.Usec*1000).Format(`"` + traceTime + `"`)
	t.Start = &tt
	t.HopCount = uint32(in.HopCount)
	t.Attempts = uint32(in.Flags.Attempts)
	t.Hoplimit = uint32(in.Flags.HopLimit)
	t.Firsthop = uint32(in.Flags.StartTTL)
	t.Wait = uint32(in.Flags.TimeoutS)
	t.WaitProbe = uint32(in.Flags.MinWaitCenti)
	t.Tos = uint32(in.Flags.IPToS)
	t.ProbeSize = uint32(in.Flags.ProbeSize)
	hops := convertHops(in)
	t.Hops = hops
	t.GapLimit = uint32(in.Flags.GapLimit)
	return t
}

func convertHops(in warts.Traceroute) []*TracerouteHop {
	hops := in.Hops
	retHops := make([]*TracerouteHop, in.HopCount)
	for i, hop := range hops {
		h := &TracerouteHop{}
		h.Addr = uint32(hop.Address.Address)
		h.ProbeTtl = uint32(hop.ProbeTTL)
		h.ProbeId = uint32(hop.ProbeID)
		h.ProbeSize = uint32(hop.ProbeSize)
		h.Rtt = &RTT{}
		h.Rtt.Sec = hop.RTT.Sec
		h.Rtt.Usec = int64(hop.RTT.Usec)
		h.ReplyTtl = uint32(hop.ReplyTTL)
		h.ReplyTos = uint32(hop.ToS)
		h.ReplySize = uint32(hop.ReplySize)
		h.ReplyIpid = uint32(hop.IPID)
		h.IcmpType = uint32((hop.ICMPTypeCode & 0xFF00) >> 8)
		h.IcmpCode = uint32(hop.ICMPTypeCode & 0x00FF)
		h.IcmpQTtl = uint32(hop.QuotedTTL)
		h.IcmpQIpl = uint32(hop.QuotedIPLength)
		h.IcmpQTos = uint32(hop.QuotesToS)
		retHops[i] = h
	}
	return retHops
}

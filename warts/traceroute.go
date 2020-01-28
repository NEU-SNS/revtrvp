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
	"fmt"
	"io"
	"syscall"
)

// Traceroute is a warts traceroute
type Traceroute struct {
	Flags      TracerouteFlags
	PLength    uint16
	HopCount   uint16
	Hops       []TracerouteHop
	EndOfTrace uint16
}

// TracerouteHop is a warts traceroute hop
type TracerouteHop struct {
	PLength        uint16
	HopAddr        Address
	ProbeTTL       uint8
	ReplyTTL       uint8
	Flags          uint8
	ProbeID        uint8
	RTT            syscall.Timeval
	ICMPTypeCode   uint16
	ProbeSize      uint16
	ReplySize      uint16
	IPID           uint16
	ToS            uint8
	NextHopMTU     uint16
	QuotedIPLength uint16
	QuotedTTL      uint8
	TCPFlags       uint8
	QuotesToS      uint8
	ICMPExt        ICMPExtensionList
	Address        Address
}

// ICMPExtension is an icmp extension
type ICMPExtension struct {
	Length      uint16
	ClassNumber uint8
	TypeNumber  uint8
	Data        []byte
}

func readICMPExtension(f io.Reader) (ICMPExtension, error) {
	ret := ICMPExtension{}
	length, err := readUint16(f)
	if err != nil {
		return ret, err
	}
	class, err := readUint8(f)
	if err != nil {
		return ret, err
	}
	typen, err := readUint8(f)
	if err != nil {
		return ret, err
	}
	ret.Length = length
	ret.ClassNumber = class
	ret.TypeNumber = typen
	data, err := readBytes(f, int(length))
	if err != nil {
		return ret, err
	}
	ret.Data = data
	return ret, nil
}

// ICMPExtensionList is an list of icmp extensions
type ICMPExtensionList struct {
	Length     uint16
	Extensions []ICMPExtension
}

func readICMPExtensionList(f io.Reader) (ICMPExtensionList, error) {
	ret := ICMPExtensionList{}
	length, err := readUint16(f)
	if err != nil {
		return ret, err
	}
	ret.Length = length
	ret.Extensions = make([]ICMPExtension, 0)
	for i := uint16(0); i < length; {
		ext, err := readICMPExtension(f)
		if err != nil {
			return ret, err
		}
		ret.Extensions = append(ret.Extensions, ext)
		i += ext.Length + 2 + 2
	}
	return ret, nil
}

// TracerouteFlags are the traceroute flags of a warts traceroute
type TracerouteFlags struct {
	ListID       uint32
	CycleID      uint32
	SrcID        Address
	DstID        Address
	StartTime    syscall.Timeval
	StopReason   StopReason
	StopData     uint8
	TraceFlags   uint8
	Attempts     uint8
	HopLimit     uint8
	TraceType    TraceType
	ProbeSize    uint16
	SourcePort   uint16
	DestPort     uint16
	StartTTL     uint8
	IPToS        uint8
	TimeoutS     uint8
	Loops        uint8
	HopsProbed   uint16
	GapLimit     uint8
	GapAction    uint8
	LoopAction   uint8
	ProbesSent   uint16
	MinWaitCenti uint8
	Confidence   uint8
	Src          Address
	Dst          Address
	UserID       uint32
}

// TraceType is the type of the traceroute
type TraceType uint8

func (tt TraceType) String() string {
	types := []string{
		"NULL",
		"icmp-echo",
		"udp",
		"tcp",
		"icmp-echo-paris",
		"udp-paris",
		"tcp-ack",
	}
	return types[tt]
}

// StopReason is the reason the traceroute stopped
type StopReason uint8

func (sr StopReason) String() string {
	reasons := []string{
		"NONE",
		"COMPLETED",
		"UNREACH",
		"ICMP",
		"LOOP",
		"GAPLIMIT",
		"ERROR",
		"HOPLIMIT",
		"GSS",
		"HALTED",
	}
	return reasons[sr]
}

func (tf TracerouteFlags) String() string {
	return fmt.Sprintf(
		"\nListID: %d\n"+
			"CycleID: %d\n"+
			"Src: %s\n"+
			"Dst: %s\n"+
			"Start Time: %v\n"+
			"Stop Reason: %d\n"+
			"Hop Limit: %d\n"+
			"Trace Flags: %d\n"+
			"Attempts: %d\n"+
			"TraceType: %d\n"+
			"Probe Size: %d\n"+
			"Source Port: %d\n"+
			"Dest. Port: %d\n"+
			"StartTTL: %d\n"+
			"IPToS: %d\n"+
			"Timeout: %d\n"+
			"Loops: %d\n"+
			"HopsProbed: %d\n"+
			"GapLimit: %d\n"+
			"GapAction: %d\n"+
			"LoopAction: %d\n"+
			"ProbesSent: %d\n"+
			"Min Wait: %d\n"+
			"Confidence: %d\n"+
			"UserID: %d\n",
		tf.ListID,
		tf.CycleID,
		tf.Src,
		tf.Dst,
		tf.StartTime,
		tf.StopReason,
		tf.HopLimit,
		tf.TraceFlags,
		tf.Attempts,
		tf.TraceType,
		tf.ProbeSize,
		tf.SourcePort,
		tf.DestPort,
		tf.StartTTL,
		tf.IPToS,
		tf.TimeoutS,
		tf.Loops,
		tf.HopsProbed,
		tf.GapLimit,
		tf.GapAction,
		tf.LoopAction,
		tf.ProbesSent,
		tf.MinWaitCenti,
		tf.Confidence,
		tf.UserID,
	)
}

func readTraceroute(f io.Reader) (Traceroute, error) {
	var trace Traceroute
	addrs := NewAddressRefs()
	var err error
	trace.Flags, err = readTracerouteFlags(f, addrs)

	if err != nil {
		return trace, err
	}
	hc, err := readUint16(f)
	if err != nil {
		return trace, err
	}
	trace.HopCount = hc
	hops, err := readTracerouteHops(f, hc, addrs)
	if err != nil {
		return trace, err
	}
	trace.Hops = hops
	_, err = readUint16(f)
	if err != nil {
		return trace, err
	}
	return trace, nil
}

func readTracerouteHops(f io.Reader, count uint16, addrs *AddressRefs) ([]TracerouteHop, error) {
	ret := make([]TracerouteHop, count)
	for i := uint16(0); i < count; i++ {
		th, err := readTracerouteHop(f, addrs)
		if err != nil {
			return nil, err
		}
		ret[i] = th
	}
	return ret, nil
}

func readTracerouteHop(f io.Reader, addrs *AddressRefs) (TracerouteHop, error) {
	th := TracerouteHop{}
	first, err := readBytes(f, 1)
	if err != nil {
		return th, err
	}
	flags, err := getFlags(f, first[0])
	if err != nil {
		return th, err
	}
	if len(flags) != 0 {
		_, err := readUint16(f)
		if err != nil {
			return th, err
		}
	}
	for _, flag := range flags {
		switch flag {
		case 1:
			th.HopAddr, err = readReferencedAddress(f, addrs)
			if err != nil {
				return th, err
			}
		case 2:
			th.ProbeTTL, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 3:
			th.ReplyTTL, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 4:
			th.Flags, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 5:
			th.ProbeID, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 6:
			val, err := readUint32(f)
			if err != nil {
				return th, err
			}
			convertTimeval(&th.RTT, val)
		case 7:
			th.ICMPTypeCode, err = readUint16(f)
			if err != nil {
				return th, err
			}
			/*
				case 8:
					if err != nil {
						return th, err
					}
			*/
		case 8:
			th.ProbeSize, err = readUint16(f)
			if err != nil {
				return th, err
			}
		case 9:
			th.ReplySize, err = readUint16(f)
			if err != nil {
				return th, err
			}
		case 10:
			th.IPID, err = readUint16(f)
			if err != nil {
				return th, err
			}
		case 11:
			th.ToS, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 12:
			th.NextHopMTU, err = readUint16(f)
			if err != nil {
				return th, err
			}
		case 13:
			th.QuotedIPLength, err = readUint16(f)
			if err != nil {
				return th, err
			}
		case 14:
			th.QuotedTTL, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 15:
			th.TCPFlags, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 16:
			th.QuotesToS, err = readUint8(f)
			if err != nil {
				return th, err
			}
		case 17:
			th.ICMPExt, err = readICMPExtensionList(f)
			if err != nil {
				return th, err
			}
		case 18:
			th.Address, err = readAddress(f, addrs)
			if err != nil {
				return th, err
			}
		default:
			return th, fmt.Errorf("Invalid flag in traceroute reply")
		}
	}
	return th, nil
}

func readTracerouteFlags(f io.Reader, addrs *AddressRefs) (TracerouteFlags, error) {
	tf := TracerouteFlags{}
	first := make([]byte, 1)
	n, err := f.Read(first)
	if err != nil {
		return tf, nil
	}
	if n != 1 {
		return tf, fmt.Errorf("Failed to read, readTracerouteFlags")
	}

	flags, err := getFlags(f, uint8(first[0]))
	if err != nil {
		return tf, err
	}
	if len(flags) != 0 {
		_, err := readUint16(f)
		if err != nil {
			return tf, err
		}
	}
	for _, flag := range flags {
		switch flag {
		case 1:
			tf.ListID, err = readUint32(f)
			if err != nil {
				return tf, err
			}
		case 2:
			tf.CycleID, err = readUint32(f)
			if err != nil {
				return tf, err
			}
		case 3:
			tf.SrcID, err = readReferencedAddress(f, addrs)
			if err != nil {
				return tf, err
			}
		case 4:
			tf.DstID, err = readReferencedAddress(f, addrs)
			if err != nil {
				return tf, err
			}
		case 5:
			tf.StartTime, err = readTimeVal(f)
			if err != nil {
				return tf, err
			}
		case 6:
			ret, err := readUint8(f)
			if err != nil {
				return tf, err
			}
			tf.StopReason = StopReason(ret)
		case 7:
			tf.StopData, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 8:
			tf.TraceFlags, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 9:
			tf.Attempts, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 10:
			tf.HopLimit, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 11:
			val, err := readUint8(f)
			if err != nil {
				return tf, err
			}
			tf.TraceType = TraceType(val)
		case 12:
			tf.ProbeSize, err = readUint16(f)
			if err != nil {
				return tf, err
			}
		case 13:
			tf.SourcePort, err = readUint16(f)
			if err != nil {
				return tf, err
			}
		case 14:
			tf.DestPort, err = readUint16(f)
			if err != nil {
				return tf, err
			}
		case 15:
			tf.StartTTL, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 16:
			tf.IPToS, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 17:
			tf.TimeoutS, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 18:
			tf.Loops, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 19:
			tf.HopsProbed, err = readUint16(f)
			if err != nil {
				return tf, err
			}
		case 20:
			tf.GapLimit, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 21:
			tf.GapAction, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 22:
			tf.LoopAction, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 23:
			tf.ProbesSent, err = readUint16(f)
			if err != nil {
				return tf, err
			}
		case 24:
			tf.MinWaitCenti, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 25:
			tf.Confidence, err = readUint8(f)
			if err != nil {
				return tf, err
			}
		case 26:
			tf.Src, err = readAddress(f, addrs)
			if err != nil {
				return tf, err
			}
		case 27:
			tf.Dst, err = readAddress(f, addrs)
			if err != nil {
				return tf, err
			}
		case 28:
			tf.UserID, err = readUint32(f)
			if err != nil {
				return tf, err
			}
		default:
			return tf, fmt.Errorf("Parsed a flag that shouldn't be there: readTracerouteFlags")
		}
	}
	return tf, nil
}

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
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/util"
	"github.com/golang/protobuf/proto"
)

// TTime is a time that matches the format of the time in a warts traceroute
type TTime time.Time

const traceTime = "2006-01-_2 15:04:05"

// UnmarshalJSON satisfies the json packages interface
func (t *TTime) UnmarshalJSON(data []byte) (err error) {
	temp, err := time.Parse(`"`+traceTime+`"`, string(data))
	*t = TTime(temp)
	return
}

// MarshalJSON satisfies the json packages interface
func (t TTime) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if y := tt.Year(); y < 0 || y >= 10000 {
		return nil, errors.New("TTime.MarshalJSON: year outside of range [0,9999]")
	}
	return []byte(tt.Format(`"` + traceTime + `"`)), nil
}

func (t TTime) String() string {
	tt := time.Time(t)
	return tt.String()
}

// Key generates a chache key for a Traceroute
func (t *Traceroute) Key() string {
	return fmt.Sprintf("%s_%d_%d", "XXTR", t.Src, t.Dst)
}

// CUnmarshal unmarshals a traceroute which is retrieved from a cache
func (t *Traceroute) CUnmarshal(data []byte) error {
	return proto.Unmarshal(data, t)
}

// CMarshal marshals a traceroute for storing in a cache
func (t *Traceroute) CMarshal() []byte {
	ret, err := proto.Marshal(t)
	if err != nil {
		return nil
	}
	return ret
}

// ErrorString generates an error string for a traceroute
// which is used to print error messages in reverse traceroute
func (t *Traceroute) ErrorString() string {
	var buf bytes.Buffer
	ssrc, _ := util.Int32ToIPString(t.Src)
	sdst, _ := util.Int32ToIPString(t.Dst)
	_, err := buf.WriteString(fmt.Sprintf("Trace from %s to %s\n", ssrc, sdst))
	if err != nil {
		return err.Error()
	}
	last := new(int)
	for i, hop := range t.GetHops() {
		if i > 0 && int(hop.ProbeTtl) != int(t.GetHops()[i-1].ProbeTtl)+1 {
			log.Debug("ttl: ", hop.ProbeTtl, " i: ", i)
			for j := int(t.GetHops()[i-1].ProbeTtl) + 1; j < int(hop.ProbeTtl); j++ {
				_, err := buf.WriteString(fmt.Sprintf("%d: *   *   *\n", j))
				if err != nil {
					return err.Error()
				}
			}
		}
		hops, _ := util.Int32ToIPString(hop.Addr)
		_, err := buf.WriteString(fmt.Sprintf("%d: %s\n", hop.ProbeTtl, hops))
		if err != nil {
			return err.Error()
		}
		*last = int(hop.ProbeTtl)
	}
	if t.StopReason == "GAPLIMIT" {
		for i := 0; i < 5; i++ {
			buf.WriteString(fmt.Sprintf("%d: *   *   *\n", *last+i+1))
		}

	}
	_, err = buf.WriteString("Stop Reason: " + t.StopReason + "\n")
	if err != nil {
		return err.Error()
	}
	return buf.String()
}

// CMarshal marshals a traceroute measurement for storing in a cache
func (tm *TracerouteMeasurement) CMarshal() []byte {
	ret, err := proto.Marshal(tm)
	if err != nil {
		return nil
	}
	return ret
}

// Key generates a key for storing a traceroute measurement in a cache
func (tm *TracerouteMeasurement) Key() string {
	return fmt.Sprintf("%s_%d_%d", "XXTR", tm.Src, tm.Dst)
}

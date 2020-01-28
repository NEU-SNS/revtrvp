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

package uuencode_test

import (
	"testing"

	"github.com/NEU-SNS/revtr-vp/uuencode"
)

func TestEncode(t *testing.T) {
	for _, test := range []struct {
		raw string
		enc string
	}{
		{raw: "this is a test string", enc: "5=&AI<R!I<R!A('1E<W0@<W1R:6YG\n`\n"},
		{raw: "short test", enc: "*<VAO<G0@=&5S=```\n`\n"},
		{raw: "This is a much longer test which should make for multiple lines",
			enc: "M5&AI<R!I<R!A(&UU8V@@;&]N9V5R('1E<W0@=VAI8V@@<VAO=6QD(&UA:V4@\n29F]R(&UU;'1I<&QE(&QI;F5S\n`\n"},
	} {
		enc, err := uuencode.UUEncode([]byte(test.raw))
		if err != nil {
			t.Fatalf("Error encoding. Got[%v], expected[<nil>]", err)
		}
		if string(enc) != test.enc {
			t.Fatalf("Error encoding. Got[%s], expected[%s]", string(enc), test.enc)
		}
	}
}

func TestDecode(t *testing.T) {
	for _, test := range []struct {
		dec string
		enc string
	}{
		{dec: "this is a test string", enc: "5=&AI<R!I<R!A('1E<W0@<W1R:6YG\n`\n"},
		{dec: "short test", enc: "*<VAO<G0@=&5S=```\n`\n"},
		{dec: "This is a much longer test which should make for multiple lines",
			enc: "M5&AI<R!I<R!A(&UU8V@@;&]N9V5R('1E<W0@=VAI8V@@<VAO=6QD(&UA:V4@\n29F]R(&UU;'1I<&QE(&QI;F5S\n`\n"},
	} {
		dec, err := uuencode.UUDecode([]byte(test.enc))
		if err != nil {
			t.Fatalf("Error decoding. Got[%v], expected[<nil>]", err)
		}
		if string(dec) != test.dec {
			t.Fatalf("Error encoding. Got[%s], expected[%s]", string(dec), test.dec)
		}
	}
}

func BenchmarkEncode(b *testing.B) {
	enc := []byte("This is a much longer test which should make for multiple lines")
	for i := 0; i < b.N; i++ {
		_, err := uuencode.UUEncode(enc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

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
package cache_test

import (
	"testing"

	"github.com/NEU-SNS/revtr-vp/cache"
)

var list = cache.ServerList{"127.0.0.1:11211"}

func TestNewCache(t *testing.T) {
	c := cache.New(list)
	if c == nil {
		t.Error("Nil cache in TestNewCache")
	}
}

func TestGet(t *testing.T) {
	c := cache.New(list)
	if c == nil {
		t.Error("Nil cache in TestNewCache")
	}
	key := "TestKey"
	testval := "Test Value"
	c.Set(key, []byte(testval))
	it, err := c.Get(key)
	if err != nil {
		t.Fatalf("TestGet failed: %v", err)
	}
	sv := string(it.Value())
	if sv != testval {
		t.Fatalf("TestGet Failed. Got: %s, Expected: %s", sv, testval)
	}
}

func TestGetMulti(t *testing.T) {
	c := cache.New(list)
	if c == nil {
		t.Error("Nil cache in TestNewCache")
	}
	key := "TestKey"
	testval := "Test Value"
	key1 := "TestKey1"
	testval1 := "Test Value"
	key2 := "TestKey2"
	testval2 := "Test Value"

	c.Set(key, []byte(testval))
	c.Set(key1, []byte(testval1))
	c.Set(key2, []byte(testval2))
	keys := []string{key, key1, key2}
	res, err := c.GetMulti(keys)
	if err != nil {
		t.Fatalf("TestGetMulti failed: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("TestGetMulti: wrong number of results returned. Expected: 3, Got: %d. %v", len(res), res)
	}
	for k, v := range res {
		switch k {
		case key:
			if testval != string(v.Value()) {
				t.Fatalf("TestGetMulti: key did not match value. Expected: %s, Got: %s", testval, v.Value())
			}
		case key1:
			if testval1 != string(v.Value()) {
				t.Fatalf("TestGetMulti: key did not match value. Expected: %s, Got: %s", testval1, v.Value())
			}
		case key2:
			if testval2 != string(v.Value()) {
				t.Fatalf("TestGetMulti: key did not match value. Expected: %s, Got: %s", testval2, v.Value())
			}
		default:
			t.Fatalf("TestGetMulti: got key that was not added: %s", k)
		}
	}
}

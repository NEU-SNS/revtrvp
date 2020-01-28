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

package config

import (
	"flag"
	"os"
	"strings"
)

var envPrefix string

// SetEnvPrefix Sets the prefix to environment variables
// When the prefix is set, env variables will be looked
// for starting with pre_name
func SetEnvPrefix(pre string) {
	envPrefix = pre
}

type env struct {
	env map[string]*string
}

func newEnv() *env {
	split := "="
	en := make(map[string]*string)

	for _, val := range os.Environ() {
		split := strings.SplitN(val, split, 2)
		en[split[0]] = &split[1]
	}
	return &env{env: en}
}

func (e *env) Get(key string) *string {
	return e.env[key]
}

func mergeEnvironment(f *flag.FlagSet) error {
	env := newEnv()
	fn := func(name string) *string {
		sep := "_"
		if envPrefix == "" {
			sep = ""
		}
		key := strings.ToUpper(strings.Join(
			[]string{
				envPrefix,
				strings.Replace(name, "-", "_", -1),
			},
			sep,
		))
		return env.Get(key)
	}
	err := merge(f, fn)
	return err
}

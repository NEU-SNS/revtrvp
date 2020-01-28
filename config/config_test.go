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

package config_test

import (
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/NEU-SNS/revtrvp/config"
)

type SubConfig struct {
	Name string `flag:"sub-name"`
	Age  int    `flag:"sub-age"`
}

type Config struct {
	Name   string `flag:"name"`
	Num    int    `flag:"num"`
	SubCon SubConfig
}

const testingConfig = `
name: Rob
num: 65
subcon:
    name: Rob
    age: 25
`

var testConfig = Config{
	Name: "Rob",
	Num:  65,
	SubCon: SubConfig{
		Name: "Rob",
		Age:  25,
	},
}

func TestEnv(t *testing.T) {
	args := []string{"dummy", "dummy"}
	env := map[string]string{
		"NAME":     "Rob",
		"NUM":      "65",
		"SUB_NAME": "Rob",
		"SUB_AGE":  "25",
	}
	for k, v := range env {
		if err := os.Setenv(k, v); err != nil {
			t.Fatal("TestEnv: ", err)
		}
	}
	defer func() {
		for k := range env {
			if err := os.Unsetenv(k); err != nil {
				t.Fatal("TestEnv ", err)
			}
		}
	}()
	os.Args = args
	var conf Config
	flags := flag.NewFlagSet("Test", flag.ContinueOnError)
	flags.StringVar(&conf.Name, "name", "", "")
	flags.StringVar(&conf.SubCon.Name, "sub-name", "", "")
	flags.IntVar(&conf.Num, "num", 0, "")
	flags.IntVar(&conf.SubCon.Age, "sub-age", 0, "")
	err := config.Parse(flags, &conf)
	if err != nil && !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatal("Error Parsing flags: ", err)
	}
	if testConfig != conf {
		t.Fatalf("Parseing ENV failed. Expected[%v] got[%v]", testConfig, conf)
	}
}

func TestFile(t *testing.T) {
	args := []string{"dummy", "dummy"}
	os.Args = args
	fileName := "revtr.Config"
	tmpfile, err := ioutil.TempFile("", fileName)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write([]byte(testingConfig))
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	config.AddConfigPath(tmpfile.Name())
	tmpfile.Close()
	var conf Config
	flags := flag.NewFlagSet("Test", flag.ContinueOnError)
	flags.StringVar(&conf.Name, "name", "", "")
	flags.StringVar(&conf.SubCon.Name, "sub-name", "", "")
	flags.IntVar(&conf.Num, "num", 0, "")
	flags.IntVar(&conf.SubCon.Age, "sub-age", 0, "")
	err = config.Parse(flags, &conf)
	if err != nil && !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatal("Error Parsing flags: ", err)
	}
	if testConfig != conf {
		t.Fatalf("Parseing ENV failed. Expected[%v] got[%v]", testConfig, conf)
	}
}

func TestParse(t *testing.T) {
	var conf Config
	flags := flag.NewFlagSet("Test", flag.ContinueOnError)
	flags.StringVar(&conf.Name, "name", "", "")
	flags.StringVar(&conf.SubCon.Name, "sub-name", "", "")
	flags.IntVar(&conf.Num, "num", 0, "")
	flags.IntVar(&conf.SubCon.Age, "sub-age", 0, "")
	err := config.Parse(flags, conf)
	if err != config.ErrorInvalidType && !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("Error parsing config Expected[%v] got[%v]", config.ErrorInvalidType, err)
	}
}

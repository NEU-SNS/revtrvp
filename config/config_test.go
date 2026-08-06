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

// PtrConfig mirrors the pointer-field style plvp.Conf actually uses (see
// plvp/types.go), rather than TestEnv/TestFile's plain-value Config. With
// pointer fields, buildMap can tell "this key was absent from this
// particular YAML file" (nil, skipped) apart from "present with a zero
// value", which plain fields cannot. It also uses flag names distinct
// from Config/SubConfig's so it isn't affected by config paths other
// tests register in the package-level (never reset) configFiles.
//
// Note YAML keys match the (lowercased) field name, not the flag tag —
// same as production's plvp.Conf, which has no yaml tags either.
type PtrConfig struct {
	Name *string `flag:"env-file-name"`
	Num  *int    `flag:"env-file-num"`
}

// TestEnvOverridesFile verifies the precedence documented in doc.go:
// "Command line flags take precedent over environment variables which
// take precedent over config files." A config file value must not
// clobber a value already supplied via an environment variable, and a
// config file value must still apply for keys nothing else set.
func TestEnvOverridesFile(t *testing.T) {
	args := []string{"dummy", "dummy"}
	os.Args = args

	if err := os.Setenv("ENV_FILE_NAME", "FromEnv"); err != nil {
		t.Fatal("TestEnvOverridesFile: ", err)
	}
	defer func() {
		if err := os.Unsetenv("ENV_FILE_NAME"); err != nil {
			t.Fatal("TestEnvOverridesFile: ", err)
		}
	}()

	fileName := "revtr.Config"
	tmpfile, err := ioutil.TempFile("", fileName)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err = tmpfile.Write([]byte("name: FromFile\nnum: 65\n")); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	config.AddConfigPath(tmpfile.Name())
	tmpfile.Close()

	// Fields must be pre-allocated before binding, matching how the real
	// plvp.Conf is constructed (see plvp/types.go's Default()).
	conf := PtrConfig{Name: new(string), Num: new(int)}
	flags := flag.NewFlagSet("Test", flag.ContinueOnError)
	flags.StringVar(conf.Name, "env-file-name", "", "")
	flags.IntVar(conf.Num, "env-file-num", 0, "")
	err = config.Parse(flags, &conf)
	if err != nil && !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatal("Error Parsing flags: ", err)
	}
	if conf.Name == nil || *conf.Name != "FromEnv" {
		t.Fatalf("Expected env var to take precedence over config file. Expected[FromEnv] got[%v]", conf.Name)
	}
	// The file-only key should still apply, since nothing else set it.
	if conf.Num == nil || *conf.Num != 65 {
		t.Fatalf("Expected file value to apply for keys not set elsewhere. Expected[65] got[%v]", conf.Num)
	}
}

// UnregisteredFlagConfig has a "flag" tag (Unbound) with no corresponding
// flag.XxxVar registration anywhere - mirroring plvp.Conf.Scamper.CAFile
// in production, which has a flag tag but is never bound via flag.XxxVar
// in main.go. Such a field can only ever be set by a config file; there
// is no flag or env var path for it. mergeFiles must still set it
// directly from the file, matching the original (pre-precedence-fix)
// behavior for these fields.
type UnregisteredFlagConfig struct {
	Unbound *string `flag:"unbound-name"`
}

// TestFileSetsUnregisteredFlag is a regression test for a real bug
// found in revtrvp's plvp.Conf.Scamper.CAFile: switching mergeFiles to
// unmarshal into a scratch copy (to fix precedence) broke every field
// that has a "flag" tag but no actual flag.XxxVar registration, because
// such a field is invisible to the flag-based merge/handleFile
// mechanism - it can only be set by unmarshaling directly onto the live
// struct. CAFile going permanently nil caused a nil pointer dereference
// panic (plvantagepoint.go:240) in every revtrvp instance, since v0.4.0
// never registers "ca-file" as a flag, and NewConfig() never
// pre-allocates it either.
func TestFileSetsUnregisteredFlag(t *testing.T) {
	args := []string{"dummy", "dummy"}
	os.Args = args

	tmpfile, err := ioutil.TempFile("", "revtr.Config")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err = tmpfile.Write([]byte("unbound: FromFile\n")); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	config.AddConfigPath(tmpfile.Name())
	tmpfile.Close()

	// No flags.StringVar call at all for "unbound-name" - deliberately,
	// matching CAFile/"ca-file" never being registered in main.go.
	conf := UnregisteredFlagConfig{}
	flags := flag.NewFlagSet("Test", flag.ContinueOnError)
	err = config.Parse(flags, &conf)
	if err != nil && !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatal("Error Parsing flags: ", err)
	}
	if conf.Unbound == nil || *conf.Unbound != "FromFile" {
		t.Fatalf("Expected file to set a field with no registered flag. Expected[FromFile] got[%v]", conf.Unbound)
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

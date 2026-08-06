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

// Package config is used to merge env file and command line config options
package config

import (
	"flag"
	"io/ioutil"
	"os"
	"reflect"
	"sort"

	"gopkg.in/yaml.v2"
)

func parseYamlConfig(path string, opts interface{}) error {
	f, err := os.Open(path)
	if err != nil && os.IsNotExist(err) {
		var ret error
		if os.IsNotExist(err) {
			// Return nil, not a problem if we don't find a config file
			ret = nil
		} else {
			ret = err
		}
		return ret
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, opts)
	if err != nil {
		return err
	}
	return nil
}

type configPath struct {
	Path  string
	Order int
}

type files struct {
	LastConfig  int
	ConfigPaths map[string]configPath
}

func (f *files) AddConfigPath(path string) {
	order := f.LastConfig
	f.LastConfig++
	cp := configPath{Path: path, Order: order}
	if f.ConfigPaths == nil {
		f.ConfigPaths = make(map[string]configPath)
	}
	f.ConfigPaths[path] = cp
}

var configFiles files

// AddConfigPath added the path to possible config files
func AddConfigPath(path string) {
	configFiles.AddConfigPath(path)
}

type configPathOrder []configPath

func (cp configPathOrder) Len() int           { return len(cp) }
func (cp configPathOrder) Swap(i, j int)      { cp[i], cp[j] = cp[j], cp[i] }
func (cp configPathOrder) Less(i, j int) bool { return cp[i].Order < cp[j].Order }

func mergeFiles(f *flag.FlagSet, opts interface{}) error {
	paths := make([]configPath, len(configFiles.ConfigPaths))
	var i int
	for _, val := range configFiles.ConfigPaths {
		paths[i] = val
		i++
	}
	sort.Sort(configPathOrder(paths))

	// parseYamlConfig unmarshals each file directly onto the live opts,
	// as it always has - this is what makes fields with no corresponding
	// registered flag (e.g. a struct field with a "flag" tag that main
	// never actually binds via flag.XxxVar) still get set from a config
	// file at all, since those can only ever come from a file.
	//
	// For fields that DO have a registered flag and were already set by
	// a higher-precedence source (a command line flag or environment
	// variable), that unconditional unmarshal would clobber the higher-
	// precedence value. snapshotProtected/restoreProtected undo that:
	// snapshot those fields' values before any file is applied, then
	// restore them after each file, so a file can still freely set
	// anything not already set elsewhere.
	protected := snapshotProtected(f, opts)
	for _, path := range paths {
		if err := parseYamlConfig(path.Path, opts); err != nil {
			return err
		}
		restoreProtected(protected)
	}
	return nil
}

// protectedField pairs a settable struct field with the value it held
// before any config file was applied.
type protectedField struct {
	field reflect.Value
	saved reflect.Value
}

func snapshotProtected(f *flag.FlagSet, opts interface{}) []protectedField {
	setFlags := make(map[string]bool)
	f.Visit(func(fl *flag.Flag) {
		setFlags[fl.Name] = true
	})
	var protected []protectedField
	walkFields(reflect.ValueOf(opts), func(fv reflect.Value, tag string) {
		if tag == "" || !setFlags[tag] {
			return
		}
		// For a pointer field, config.Parse's flag/env layers set the
		// value by writing through the pointer (*p = val), never by
		// replacing the field with a new pointer - and empirically,
		// yaml.Unmarshal decoding into an already-non-nil pointer field
		// does the same (mutates in place, reusing the pointer). So the
		// field itself is never a useful thing to snapshot: it's the
		// same pointer before and after. Snapshot/restore the
		// dereferenced value instead, which is where the actual content
		// - and the risk of a file clobbering it - lives.
		target := fv
		if fv.Kind() == reflect.Ptr {
			if fv.IsNil() {
				return
			}
			target = fv.Elem()
		}
		saved := reflect.New(target.Type()).Elem()
		saved.Set(target)
		protected = append(protected, protectedField{field: target, saved: saved})
	})
	return protected
}

func restoreProtected(protected []protectedField) {
	for _, p := range protected {
		p.field.Set(p.saved)
	}
}

// walkFields calls fn for every leaf (non-struct) field reachable from
// v, a pointer to a struct, recursing into nested (non-pointer) structs.
// fn receives the field's "flag" struct tag, which may be empty.
func walkFields(v reflect.Value, fn func(field reflect.Value, tag string)) {
	elem := v.Elem()
	t := elem.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fv := elem.Field(i)
		if field.Type.Kind() == reflect.Struct {
			walkFields(fv.Addr(), fn)
			continue
		}
		fn(fv, field.Tag.Get("flag"))
	}
}

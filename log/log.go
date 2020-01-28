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

package log

import (
	"flag"
	"io"
	"os"
	"path"
	"runtime"

	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

// GetLogger returns the current logger
func GetLogger() Logger {
	return logger
}

// Fields are fields to add to a log entry
type Fields map[string]interface{}

// WithFields returns a logger that will log the next line
// with the given fields
func WithFields(f Fields) Logger {
	return callerInfo(0).WithFields(logrus.Fields(f))
}

// WithFieldDepth works like WithFields but allows to set the depth
// so the line info is correct
func WithFieldDepth(f Fields, depth int) Logger {
	return callerInfo(depth).WithFields(logrus.Fields(f))
}

// Logger is the interface that the logging package supports
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Printf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})
	Debug(args ...interface{})
	Info(args ...interface{})
	Print(args ...interface{})
	Warn(args ...interface{})
	Warning(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
	Panic(args ...interface{})
	Debugln(args ...interface{})
	Infoln(args ...interface{})
	Println(args ...interface{})
	Warnln(args ...interface{})
	Warningln(args ...interface{})
	Errorln(args ...interface{})
	Fatalln(args ...interface{})
	Panicln(args ...interface{})
}

type logLevel struct{}

func (ll logLevel) String() string {
	return logger.Level.String()
}

func (ll logLevel) Set(l string) error {
	level, err := logrus.ParseLevel(l)
	if err != nil {
		return err
	}
	logger.Level = level
	return nil
}

func handleLogFile(path string) (io.Writer, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

type logOutput struct {
	out string
}

func (lo logOutput) String() string {
	return lo.out
}

func (lo logOutput) Set(out string) error {
	switch out {
	case "stdout":
		logger.Out = os.Stdout
	case "stderr":
		logger.Out = os.Stderr
	default:
		w, err := handleLogFile(out)
		if err != nil {
			return err
		}
		logger.Out = w
		return nil
	}
	return nil
}

func callerInfo(depth int) *logrus.Entry {
	// From std lib log library
	_, file, line, ok := runtime.Caller(2 + depth)
	if !ok {
		file = "???"
		line = 0
	}
	return logger.WithFields(
		logrus.Fields{
			"file": path.Base(file),
			"line": line,
		},
	)
}

func init() {
	flag.Var(logLevel{}, "loglevel", "Log level")
	flag.Var(logOutput{}, "logoutput", "Where to send log output")
}

func Debugf(format string, args ...interface{}) {
	callerInfo(0).Debugf(format, args...)
}

func Infof(format string, args ...interface{}) {
	callerInfo(0).Infof(format, args...)
}

func Printf(format string, args ...interface{}) {
	callerInfo(0).Printf(format, args...)
}

func Warnf(format string, args ...interface{}) {
	callerInfo(0).Warnf(format, args...)
}

func Warningf(format string, args ...interface{}) {
	callerInfo(0).Warnf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	callerInfo(0).Errorf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	callerInfo(0).Fatalf(format, args...)
}

func Panicf(format string, args ...interface{}) {
	callerInfo(0).Panicf(format, args...)
}

func Debug(args ...interface{}) {
	callerInfo(0).Debug(args...)
}

func Info(args ...interface{}) {
	callerInfo(0).Info(args...)
}

func Print(args ...interface{}) {
	callerInfo(0).Info(args...)
}

func Warn(args ...interface{}) {
	callerInfo(0).Warn(args...)
}

func Warning(args ...interface{}) {
	callerInfo(0).Warn(args...)
}

func Error(args ...interface{}) {
	callerInfo(0).Error(args...)
}

func Fatal(args ...interface{}) {
	callerInfo(0).Fatal(args...)
}

func Panic(args ...interface{}) {
	callerInfo(0).Panic(args...)
}

func Debugln(args ...interface{}) {
	callerInfo(0).Debugln(args...)
}

func Infoln(args ...interface{}) {
	callerInfo(0).Infoln(args...)
}

func Println(args ...interface{}) {
	callerInfo(0).Println(args...)
}

func Warnln(args ...interface{}) {
	callerInfo(0).Warnln(args...)
}

func Warningln(args ...interface{}) {
	callerInfo(0).Warnln(args...)
}

func Errorln(args ...interface{}) {
	callerInfo(0).Errorln(args...)
}

func Fatalln(args ...interface{}) {
	callerInfo(0).Fatalln(args...)
}

func Panicln(args ...interface{}) {
	callerInfo(0).Panicln(args...)
}

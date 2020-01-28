# log
--
    import "github.com/NEU-SNS/ReverseTraceroute/log"

Package log is the logging package used in the reverse traceroute system

## Usage

#### func  Debug

```go
func Debug(args ...interface{})
```

#### func  Debugf

```go
func Debugf(format string, args ...interface{})
```

#### func  Debugln

```go
func Debugln(args ...interface{})
```

#### func  Error

```go
func Error(args ...interface{})
```

#### func  Errorf

```go
func Errorf(format string, args ...interface{})
```

#### func  Errorln

```go
func Errorln(args ...interface{})
```

#### func  Fatal

```go
func Fatal(args ...interface{})
```

#### func  Fatalf

```go
func Fatalf(format string, args ...interface{})
```

#### func  Fatalln

```go
func Fatalln(args ...interface{})
```

#### func  Info

```go
func Info(args ...interface{})
```

#### func  Infof

```go
func Infof(format string, args ...interface{})
```

#### func  Infoln

```go
func Infoln(args ...interface{})
```

#### func  Panic

```go
func Panic(args ...interface{})
```

#### func  Panicf

```go
func Panicf(format string, args ...interface{})
```

#### func  Panicln

```go
func Panicln(args ...interface{})
```

#### func  Print

```go
func Print(args ...interface{})
```

#### func  Printf

```go
func Printf(format string, args ...interface{})
```

#### func  Println

```go
func Println(args ...interface{})
```

#### func  Warn

```go
func Warn(args ...interface{})
```

#### func  Warnf

```go
func Warnf(format string, args ...interface{})
```

#### func  Warning

```go
func Warning(args ...interface{})
```

#### func  Warningf

```go
func Warningf(format string, args ...interface{})
```

#### func  Warningln

```go
func Warningln(args ...interface{})
```

#### func  Warnln

```go
func Warnln(args ...interface{})
```

#### type Logger

```go
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
```

Logger is the interface that the logging package supports

#### func  GetLogger

```go
func GetLogger() Logger
```
GetLogger returns the current logger

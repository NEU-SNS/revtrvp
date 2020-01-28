# proc
--
    import "github.com/NEU-SNS/ReverseTraceroute/mproc/proc"

Package proc is a package for running processes

## Usage

#### type Process

```go
type Process struct {
}
```

Process represents a process

#### func  New

```go
func New(p string, pA *os.ProcAttr, argv ...string) *Process
```
New creates a new process

#### func (*Process) GetWaitStatus

```go
func (p *Process) GetWaitStatus() *os.ProcessState
```
GetWaitStatus gets the result of the OS wait syscall

#### func (*Process) HasProc

```go
func (p *Process) HasProc() bool
```
HasProc returns weather or not there is an os process associated with the
process

#### func (*Process) Kill

```go
func (p *Process) Kill() error
```
Kill kills the process

#### func (*Process) Pid

```go
func (p *Process) Pid() (int, error)
```
Pid get the pid of the process

#### func (*Process) Prog

```go
func (p *Process) Prog() string
```
Prog gets the program name

#### func (*Process) SetArg

```go
func (p *Process) SetArg(i int, arg string) error
```
SetArg sets an argument

#### func (*Process) Signal

```go
func (p *Process) Signal(sig os.Signal) error
```
Signal signals the process

#### func (*Process) Start

```go
func (p *Process) Start() (int, error)
```
Start starts a process

#### func (*Process) String

```go
func (p *Process) String() string
```

#### func (*Process) Wait

```go
func (p *Process) Wait() chan error
```
Wait waits on the process

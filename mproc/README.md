# mproc
--
    import "github.com/NEU-SNS/ReverseTraceroute/mproc"

Package mproc is a simple process manager

## Usage

#### type FailFunc

```go
type FailFunc func(err error, ps *os.ProcessState, p *proc.Process) bool
```

FailFunc is a function that is called when a process dies

#### type MProc

```go
type MProc interface {
	// ManageProcess runs the process p and returns and id to use to refer to the process or an error
	// if ka is true, the process will be restarted up to retry times
	// If you want the process to restart indef. just use MaxUint32
	ManageProcess(p *proc.Process, ka bool, retry uint, f FailFunc) (uint32, error)
	// KillAll sends SIGKILL all processes
	KillAll()
	// IntAll sends SIGINT to all processes
	IntAll()
	// EndKeepAlive stops the keep alive of process id
	EndKeepAlive(id uint32) error
	// SignalProc sends signal sig to process with id id
	SignalProc(id uint32, sig os.Signal) error
	// WaitProc waits on the process with the id id
	WaitProc(id uint32) chan error
	// GetProc gets the process with id id
	GetProc(id uint32) *proc.Process
	// KillProc kills the process with id id
	KillProc(id uint32) error
}
```

MProc is a basic process manager

#### func  New

```go
func New() MProc
```
New creates a new MProc

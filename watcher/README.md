# watcher
--
    import "github.com/NEU-SNS/ReverseTraceroute/watcher"

Package watcher watches a directory and reports back file system events

## Usage

```go
var (
	// ErrWatcherClosed is returned when the watcher is closed while waiting for an event
	ErrWatcherClosed = fmt.Errorf("The watcher was closed")
)
```

#### type Event

```go
type Event interface {
	// Name gets the name of the file associated with the event
	Name() string
	// Type gets the event type
	// Currently only create and Remove events are supported
	Type() EventType
}
```

Event represents a file system event

#### type EventType

```go
type EventType int
```

EventType represents a file system event

```go
const (
	// Create is when a file is created
	Create EventType = iota
	// Remove is when a file is removed
	Remove
)
```

#### type Watcher

```go
type Watcher interface {
	// Close closes the watcher. The path watched by the watcher is no longer being
	// watched for events
	Close() error
	// GetEvent gets the next file system event. The call will block until an event occurs.
	// The call can be unblocked by closing the channel argument
	GetEvent(chan struct{}) (Event, error)
}
```

Watcher watches a path

#### func  New

```go
func New(path string) (Watcher, error)
```
New creates a new watcher which watches the given path

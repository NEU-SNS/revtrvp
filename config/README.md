# config
--
    import "github.com/NEU-SNS/ReverseTraceroute/config"

Package config handles the config parsing for the various commands


The package merges flags from multiple sources into one object

Command line flags take precedent over environment variables which take
precedent over config files


Config files must be in yaml format

Config uses struct tags to match command line flags, config file elements and
environment variables to struct fields.

Example:

    type Config struct {
        Name string `flag:"name"`
        Dir  string `flag:"dir"`
    }

The Config struct will match ENV variables NAME and DIR, command line flags -env
and -dir as well as config file elements name: and dir:

Hyphens in flag names are converted into underscores in environment variables.

Package config is used to merge env file and command line config options

## Usage

```go
var (
	// ErrorInvalidType is returned when Parse is passed a bad opts object
	ErrorInvalidType = fmt.Errorf("Parse must be passed a non-nil pointer")
)
```

#### func  AddConfigPath

```go
func AddConfigPath(path string)
```
AddConfigPath added the path to possible config files

#### func  Parse

```go
func Parse(f *flag.FlagSet, opts interface{}) error
```
Parse fills in the flag set using environment variables and config files opts is
an object that will represent the format of the config files being parsed

#### func  SetEnvPrefix

```go
func SetEnvPrefix(pre string)
```
SetEnvPrefix Sets the prefix to environment variables When the prefix is set,
env variables will be looked for starting with pre_name

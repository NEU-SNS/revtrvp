# uuencode
--
    import "github.com/NEU-SNS/ReverseTraceroute/uuencode"

Package uuencode is a package for uuencoding bytes and decoding uuencoded bytes

## Usage

```go
var (

	// ErrorInvalidByte is the error for an invalid byte in a UUDecoding
	ErrorInvalidByte = errors.New("InvalidByte")
)
```

#### func  UUDecode

```go
func UUDecode(e []byte) ([]byte, error)
```
UUDecode decodes the uuencoded bytes in e

#### func  UUEncode

```go
func UUEncode(p []byte) ([]byte, error)
```
UUEncode encodes the bytes in p

#### type UUDecodingWriter

```go
type UUDecodingWriter struct {
}
```

UUDecodingWriter decodes uuencoded bytes that are written to it

#### func (*UUDecodingWriter) Bytes

```go
func (w *UUDecodingWriter) Bytes() []byte
```
Bytes gets the result bytes from a UUDecodingWriter

#### func (*UUDecodingWriter) Write

```go
func (w *UUDecodingWriter) Write(p []byte) (n int, err error)
```
Write uudecodes the bytes in p

# warts
--
    import "github.com/NEU-SNS/ReverseTraceroute/warts"

Package warts is a library for parsing warts files

## Usage

#### func  Parse

```go
func Parse(data []byte, objs []WartsT) ([]interface{}, error)
```
Parse parses bytes into warts objects. Only objects of the types in objs will be
returned

#### type Address

```go
type Address struct {
	Type    uint8
	Address uint64
}
```

Address represents an address

#### func (Address) String

```go
func (a Address) String() string
```

#### type AddressRefs

```go
type AddressRefs struct {
}
```

AddressRefs tracks the addresses in a warts file

#### func  NewAddressRefs

```go
func NewAddressRefs() *AddressRefs
```
NewAddressRefs creates a new AddressRefs structure

#### func (*AddressRefs) Add

```go
func (ar *AddressRefs) Add(addr Address)
```
Add adds an address to the AddressRefs

#### func (*AddressRefs) Get

```go
func (ar *AddressRefs) Get(id uint32) Address
```
Get gets an address by id from addressrefs

#### type CycleStart

```go
type CycleStart struct {
	CycleID   uint32
	ListID    uint32
	CCycleID  uint32
	StartTime uint32
	PLength   uint16
	StopTime  uint32
	Hostname  string
}
```

CycleStart is the start of a warts cycle

#### func (CycleStart) String

```go
func (c CycleStart) String() string
```

#### type CycleStartFlags

```go
type CycleStartFlags struct {
	Length   uint16
	StopTime uint32
	Hostname string
}
```

CycleStartFlags are the flags that a CycleStart can contain

#### type CycleStop

```go
type CycleStop struct {
	CycleID  uint32
	StopTime uint32
}
```

CycleStop is the end of a warts cycle

#### type CycleStopFlags

```go
type CycleStopFlags struct {
}
```

CycleStopFlags are the flags that a CycleStop can contain

#### type Header

```go
type Header struct {
	Magic  uint16
	Type   WartsT
	Length uint32
}
```

Header is the header value that a warts file uses

#### type ICMPExtension

```go
type ICMPExtension struct {
	Length      uint16
	ClassNumber uint8
	TypeNumber  uint8
	Data        []byte
}
```

ICMPExtension is an icmp extension

#### type ICMPExtensionList

```go
type ICMPExtensionList struct {
	Length     uint16
	Extensions []ICMPExtension
}
```

ICMPExtensionList is an list of icmp extensions

#### type List

```go
type List struct {
	ListID      uint32
	CListID     uint32
	ListName    string
	PLength     uint16
	Description string
	MonitorName string
}
```

List is a warts list

#### func (List) String

```go
func (l List) String() string
```

#### type ListFlags

```go
type ListFlags struct {
	Length      uint16
	Description string
	MonitorName string
}
```

ListFlags are the flags a list can have

#### type PFlags

```go
type PFlags []PingFlag
```

PFlags is a slice of PingFlags

#### type PRFlags

```go
type PRFlags []ReplyFlag
```

PRFlags is an array of ReplyFlags

#### type Ping

```go
type Ping struct {
	Flags       PingFlags
	PLength     uint16
	ReplyCount  uint16
	PingReplies []PingReplyFlags
	Version     string
	Type        string
}
```

Ping is a warts ping

#### func (Ping) GetStats

```go
func (p Ping) GetStats() PingStats
```
GetStats calculates the stats for a ping

#### func (Ping) IsTsAndAddr

```go
func (p Ping) IsTsAndAddr() bool
```
IsTsAndAddr returns true of the ping is tsandaddr

#### func (Ping) IsTsOnly

```go
func (p Ping) IsTsOnly() bool
```
IsTsOnly returns true if the ping is tsonly ts option

#### func (Ping) String

```go
func (p Ping) String() string
```

#### type PingFlag

```go
type PingFlag uint8
```

PingFlag is a flag set in a ping

#### func (PingFlag) Strings

```go
func (pf PingFlag) Strings() []string
```
Strings returns a string representation of a pingflag

#### type PingFlags

```go
type PingFlags struct {
	ListID       uint32
	CycleID      uint32
	SrcID        uint32
	DstID        uint32
	StartTime    syscall.Timeval
	StopReason   uint8
	StopData     uint8
	DataLength   uint16
	Data         []byte
	ProbeCount   uint16
	ProbeSize    uint16
	ProbeWaitS   uint8
	ProbeTTL     uint8
	ReplyCount   uint16
	PingsSent    uint16
	PingMethod   PingMethod
	ProbeSrcPort uint16
	ProbeDstPort uint16
	UserID       uint32
	Src          Address
	Dst          Address
	ProbeTOS     uint8
	TS           []Address
	ICMPChecksum uint16
	MTU          uint16
	ProbeTimeout uint8
	ProbeWait    uint32
	PingFlags    PFlags
	PF           PingFlag
}
```

PingFlags are the flags set in the ping

#### func (PingFlags) String

```go
func (pf PingFlags) String() string
```

#### type PingMethod

```go
type PingMethod uint8
```

PingMethod is the method type of the ping

#### func (PingMethod) String

```go
func (pm PingMethod) String() string
```

#### type PingReplyFlags

```go
type PingReplyFlags struct {
	DstID       uint32
	Flags       uint8
	ReplyTTL    uint8
	ReplySize   uint16
	ICMP        uint16
	RTT         syscall.Timeval
	ProbeID     uint16
	ReplyIPID   uint16
	ProbeIPID   uint16
	ReplyProto  RProto
	TCPFlags    uint8
	Addr        Address
	V4RR        V4RR
	V4TS        V4TS
	ReplyIPID32 uint32
	Tx          syscall.Timeval
	TSReply     TSReply
	ReplyFlags  PRFlags
}
```

PingReplyFlags are the flags for a ping reply

#### func (PingReplyFlags) String

```go
func (prf PingReplyFlags) String() string
```

#### type PingStats

```go
type PingStats struct {
	Replies uint16
	Loss    uint16
	Min     float32
	Max     float32
	Avg     float32
	StdDev  float32
}
```

PingStats are warts ping stats

#### type RProto

```go
type RProto uint8
```

RProto is the proto of the reply

#### func (RProto) String

```go
func (rp RProto) String() string
```

#### type ReplyFlag

```go
type ReplyFlag uint8
```

ReplyFlag is a flag in the reply

#### type StopReason

```go
type StopReason uint8
```

StopReason is the reason the traceroute stopped

#### func (StopReason) String

```go
func (sr StopReason) String() string
```

#### type TSReply

```go
type TSReply struct {
	OTimestamp uint32
	RTimestamp uint32
	TTimestamp uint32
}
```

TSReply is the reply to a timestamp probe

#### func (TSReply) String

```go
func (tsr TSReply) String() string
```

#### type TraceType

```go
type TraceType uint8
```

TraceType is the type of the traceroute

#### func (TraceType) String

```go
func (tt TraceType) String() string
```

#### type Traceroute

```go
type Traceroute struct {
	Flags      TracerouteFlags
	PLength    uint16
	HopCount   uint16
	Hops       []TracerouteHop
	EndOfTrace uint16
}
```

Traceroute is a warts traceroute

#### type TracerouteFlags

```go
type TracerouteFlags struct {
	ListID       uint32
	CycleID      uint32
	SrcID        Address
	DstID        Address
	StartTime    syscall.Timeval
	StopReason   StopReason
	StopData     uint8
	TraceFlags   uint8
	Attempts     uint8
	HopLimit     uint8
	TraceType    TraceType
	ProbeSize    uint16
	SourcePort   uint16
	DestPort     uint16
	StartTTL     uint8
	IPToS        uint8
	TimeoutS     uint8
	Loops        uint8
	HopsProbed   uint16
	GapLimit     uint8
	GapAction    uint8
	LoopAction   uint8
	ProbesSent   uint16
	MinWaitCenti uint8
	Confidence   uint8
	Src          Address
	Dst          Address
	UserID       uint32
}
```

TracerouteFlags are the traceroute flags of a warts traceroute

#### func (TracerouteFlags) String

```go
func (tf TracerouteFlags) String() string
```

#### type TracerouteHop

```go
type TracerouteHop struct {
	PLength        uint16
	HopAddr        Address
	ProbeTTL       uint8
	ReplyTTL       uint8
	Flags          uint8
	ProbeID        uint8
	RTT            syscall.Timeval
	ICMPTypeCode   uint16
	ProbeSize      uint16
	ReplySize      uint16
	IPID           uint16
	ToS            uint8
	NextHopMTU     uint16
	QuotedIPLength uint16
	QuotedTTL      uint8
	TCPFlags       uint8
	QuotesToS      uint8
	ICMPExt        ICMPExtensionList
	Address        Address
}
```

TracerouteHop is a warts traceroute hop

#### type V4RR

```go
type V4RR struct {
	Addrs []Address
}
```

V4RR is the RR option

#### func (V4RR) String

```go
func (v V4RR) String() string
```

#### func (V4RR) Strings

```go
func (v V4RR) Strings() []string
```
Strings stringifies a V4RR

#### type V4TS

```go
type V4TS struct {
	Addrs      []Address
	TimeStamps []uint32
}
```

V4TS is a timestamp option

#### func (V4TS) String

```go
func (v V4TS) String() string
```

#### type WartsT

```go
type WartsT uint32
```

WartsT represents a warts type

```go
const (
	// ListT is the list type
	ListT WartsT = 0x01
	// CycleStartT is the cyclestart type
	CycleStartT = 0x02
	// CycleDefT is the cycle def type
	CycleDefT = 0x03
	// CycleStopT is the cycle stop type
	CycleStopT = 0x04
	// AddressT is the address type
	AddressT = 0x05
	// TracerouteT is the traceroute type
	TracerouteT = 0x06
	// PingT is a the ping type
	PingT = 0x07
	// MDATracerouteT is the mdatracerotue type
	MDATracerouteT = 0x08
	// AliasResolutionT is the alias resolution type
	AliasResolutionT = 0x09
	// NeighborDiscoveryT is the neighbor discovery type
	NeighborDiscoveryT = 0x0a
	// TBitT is the tbit type
	TBitT = 0x0b
	// StingT is the sting type
	StingT = 0x0c
	// SniffT is the sniff type
	SniffT = 0x0d
)
```

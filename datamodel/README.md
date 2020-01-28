# datamodel
--
    import "github.com/NEU-SNS/ReverseTraceroute/datamodel"

Package datamodel contains the shared data structures used in the different
parts of the reverse traceroute system.

Package datamodel is a generated protocol buffer package.

It is generated from these files:

    github.com/NEU-SNS/ReverseTraceroute/datamodel/ping.proto
    github.com/NEU-SNS/ReverseTraceroute/datamodel/recspoof.proto
    github.com/NEU-SNS/ReverseTraceroute/datamodel/time.proto
    github.com/NEU-SNS/ReverseTraceroute/datamodel/traceroute.proto
    github.com/NEU-SNS/ReverseTraceroute/datamodel/update.proto
    github.com/NEU-SNS/ReverseTraceroute/datamodel/vantagepoint.proto

It has these top-level messages:

    PingMeasurement
    PingArg
    PingArgResp
    PingStats
    PingResponse
    TsAndAddr
    Ping
    RecSpoof
    Spoof
    SpoofedProbes
    SpoofedProbesResponse
    Probe
    RecordRoute
    TimeStamp
    Stamp
    NotifyRecSpoofResponse
    ReceiveSpoofedProbesResponse
    Time
    RTT
    TracerouteMeasurement
    TracerouteArg
    TracerouteArgResp
    TracerouteHop
    Traceroute
    TracerouteTime
    UpdateResponse
    VantagePoint
    VPRequest
    VPReturn
    RRSpooferRequest
    RRSpooferResponse
    TSSpooferRequest
    TSSpooferResponse

## Usage

```go
var TSType_name = map[int32]string{
	0: "TSOnly",
	1: "TSAndAddr",
	3: "TSPreSpec",
}
```

```go
var TSType_value = map[string]int32{
	"TSOnly":    0,
	"TSAndAddr": 1,
	"TSPreSpec": 3,
}
```

#### type NotifyRecSpoofResponse

```go
type NotifyRecSpoofResponse struct {
	Error string `protobuf:"bytes,1,opt,name=error" json:"error,omitempty"`
}
```


#### func (*NotifyRecSpoofResponse) Descriptor

```go
func (*NotifyRecSpoofResponse) Descriptor() ([]byte, []int)
```

#### func (*NotifyRecSpoofResponse) ProtoMessage

```go
func (*NotifyRecSpoofResponse) ProtoMessage()
```

#### func (*NotifyRecSpoofResponse) Reset

```go
func (m *NotifyRecSpoofResponse) Reset()
```

#### func (*NotifyRecSpoofResponse) String

```go
func (m *NotifyRecSpoofResponse) String() string
```

#### type Ping

```go
type Ping struct {
	Type        string          `protobuf:"bytes,1,opt,name=type" json:"type,omitempty"`
	Method      string          `protobuf:"bytes,2,opt,name=method" json:"method,omitempty"`
	Src         uint32          `protobuf:"varint,3,opt,name=src" json:"src,omitempty"`
	Dst         uint32          `protobuf:"varint,4,opt,name=dst" json:"dst,omitempty"`
	Start       *Time           `protobuf:"bytes,5,opt,name=start" json:"start,omitempty"`
	PingSent    uint32          `protobuf:"varint,6,opt,name=ping_sent" json:"ping_sent,omitempty"`
	ProbeSize   uint32          `protobuf:"varint,7,opt,name=probe_size" json:"probe_size,omitempty"`
	UserId      uint32          `protobuf:"varint,8,opt,name=user_id" json:"user_id,omitempty"`
	Ttl         uint32          `protobuf:"varint,9,opt,name=ttl" json:"ttl,omitempty"`
	Wait        uint32          `protobuf:"varint,10,opt,name=wait" json:"wait,omitempty"`
	Timeout     uint32          `protobuf:"varint,11,opt,name=timeout" json:"timeout,omitempty"`
	Flags       []string        `protobuf:"bytes,12,rep,name=flags" json:"flags,omitempty"`
	Responses   []*PingResponse `protobuf:"bytes,13,rep,name=responses" json:"responses,omitempty"`
	Statistics  *PingStats      `protobuf:"bytes,14,opt,name=statistics" json:"statistics,omitempty"`
	Error       string          `protobuf:"bytes,15,opt,name=error" json:"error,omitempty"`
	Version     string          `protobuf:"bytes,16,opt,name=version" json:"version,omitempty"`
	SpoofedFrom uint32          `protobuf:"varint,17,opt,name=spoofed_from" json:"spoofed_from,omitempty"`
	Id          int64           `protobuf:"varint,18,opt,name=id" json:"id,omitempty"`
}
```


#### func  ConvertPing

```go
func ConvertPing(in warts.Ping) Ping
```
ConvertPing converts a warts ping to a DM ping

#### func (*Ping) CMarshal

```go
func (p *Ping) CMarshal() []byte
```
CMarshal marshals a ping for the cache

#### func (*Ping) CUnmarshal

```go
func (p *Ping) CUnmarshal(data []byte) error
```
CUnmarshal is the unmarshal for data coming from the cache

#### func (*Ping) Descriptor

```go
func (*Ping) Descriptor() ([]byte, []int)
```

#### func (*Ping) GetResponses

```go
func (m *Ping) GetResponses() []*PingResponse
```

#### func (*Ping) GetStart

```go
func (m *Ping) GetStart() *Time
```

#### func (*Ping) GetStatistics

```go
func (m *Ping) GetStatistics() *PingStats
```

#### func (*Ping) Key

```go
func (p *Ping) Key() string
```
Key gets the key for a Ping

#### func (*Ping) ProtoMessage

```go
func (*Ping) ProtoMessage()
```

#### func (*Ping) Reset

```go
func (m *Ping) Reset()
```

#### func (*Ping) String

```go
func (m *Ping) String() string
```

#### type PingArg

```go
type PingArg struct {
	Pings []*PingMeasurement `protobuf:"bytes,1,rep,name=pings" json:"pings,omitempty"`
}
```


#### func (*PingArg) Descriptor

```go
func (*PingArg) Descriptor() ([]byte, []int)
```

#### func (*PingArg) GetPings

```go
func (m *PingArg) GetPings() []*PingMeasurement
```

#### func (*PingArg) ProtoMessage

```go
func (*PingArg) ProtoMessage()
```

#### func (*PingArg) Reset

```go
func (m *PingArg) Reset()
```

#### func (*PingArg) String

```go
func (m *PingArg) String() string
```

#### type PingArgResp

```go
type PingArgResp struct {
	Pings []*Ping `protobuf:"bytes,1,rep,name=pings" json:"pings,omitempty"`
}
```


#### func (*PingArgResp) Descriptor

```go
func (*PingArgResp) Descriptor() ([]byte, []int)
```

#### func (*PingArgResp) GetPings

```go
func (m *PingArgResp) GetPings() []*Ping
```

#### func (*PingArgResp) ProtoMessage

```go
func (*PingArgResp) ProtoMessage()
```

#### func (*PingArgResp) Reset

```go
func (m *PingArgResp) Reset()
```

#### func (*PingArgResp) String

```go
func (m *PingArgResp) String() string
```

#### type PingMeasurement

```go
type PingMeasurement struct {
	Src         uint32 `protobuf:"varint,1,opt,name=src" json:"src,omitempty"`
	Dst         uint32 `protobuf:"varint,2,opt,name=dst" json:"dst,omitempty"`
	SpooferAddr uint32 `protobuf:"varint,3,opt,name=spoofer_addr" json:"spoofer_addr,omitempty"`
	Spoof       bool   `protobuf:"varint,4,opt,name=spoof" json:"spoof,omitempty"`
	RR          bool   `protobuf:"varint,5,opt,name=RR" json:"RR,omitempty"`
	SAddr       string `protobuf:"bytes,6,opt,name=s_addr" json:"s_addr,omitempty"`
	Payload     string `protobuf:"bytes,7,opt,name=payload" json:"payload,omitempty"`
	Count       string `protobuf:"bytes,8,opt,name=count" json:"count,omitempty"`
	IcmpSum     string `protobuf:"bytes,9,opt,name=icmp_sum" json:"icmp_sum,omitempty"`
	Dport       string `protobuf:"bytes,10,opt,name=dport" json:"dport,omitempty"`
	Sport       string `protobuf:"bytes,11,opt,name=sport" json:"sport,omitempty"`
	Wait        string `protobuf:"bytes,12,opt,name=wait" json:"wait,omitempty"`
	Ttl         string `protobuf:"bytes,13,opt,name=ttl" json:"ttl,omitempty"`
	Mtu         string `protobuf:"bytes,14,opt,name=mtu" json:"mtu,omitempty"`
	ReplyCount  string `protobuf:"bytes,15,opt,name=reply_count" json:"reply_count,omitempty"`
	Pattern     string `protobuf:"bytes,16,opt,name=pattern" json:"pattern,omitempty"`
	Method      string `protobuf:"bytes,17,opt,name=method" json:"method,omitempty"`
	Size        string `protobuf:"bytes,18,opt,name=size" json:"size,omitempty"`
	UserId      string `protobuf:"bytes,19,opt,name=user_id" json:"user_id,omitempty"`
	Tos         string `protobuf:"bytes,20,opt,name=tos" json:"tos,omitempty"`
	TimeStamp   string `protobuf:"bytes,21,opt,name=time_stamp" json:"time_stamp,omitempty"`
	Timeout     int64  `protobuf:"varint,22,opt,name=timeout" json:"timeout,omitempty"`
	CheckCache  bool   `protobuf:"varint,23,opt,name=check_cache" json:"check_cache,omitempty"`
	CheckDb     bool   `protobuf:"varint,24,opt,name=check_db" json:"check_db,omitempty"`
	Staleness   int64  `protobuf:"varint,25,opt,name=staleness" json:"staleness,omitempty"`
}
```


#### func (*PingMeasurement) Descriptor

```go
func (*PingMeasurement) Descriptor() ([]byte, []int)
```

#### func (*PingMeasurement) Key

```go
func (pm *PingMeasurement) Key() string
```
Key gets the key for a PM

#### func (*PingMeasurement) ProtoMessage

```go
func (*PingMeasurement) ProtoMessage()
```

#### func (*PingMeasurement) Reset

```go
func (m *PingMeasurement) Reset()
```

#### func (*PingMeasurement) String

```go
func (m *PingMeasurement) String() string
```

#### type PingResponse

```go
type PingResponse struct {
	From       uint32       `protobuf:"varint,1,opt,name=from" json:"from,omitempty"`
	Seq        uint32       `protobuf:"varint,2,opt,name=seq" json:"seq,omitempty"`
	ReplySize  uint32       `protobuf:"varint,3,opt,name=reply_size" json:"reply_size,omitempty"`
	ReplyTtl   uint32       `protobuf:"varint,4,opt,name=reply_ttl" json:"reply_ttl,omitempty"`
	ReplyProto string       `protobuf:"bytes,5,opt,name=reply_proto" json:"reply_proto,omitempty"`
	Tx         *Time        `protobuf:"bytes,6,opt,name=tx" json:"tx,omitempty"`
	Rx         *Time        `protobuf:"bytes,7,opt,name=rx" json:"rx,omitempty"`
	Rtt        uint32       `protobuf:"varint,8,opt,name=rtt" json:"rtt,omitempty"`
	ProbeIpid  uint32       `protobuf:"varint,9,opt,name=probe_ipid" json:"probe_ipid,omitempty"`
	ReplyIpid  uint32       `protobuf:"varint,10,opt,name=reply_ipid" json:"reply_ipid,omitempty"`
	IcmpType   uint32       `protobuf:"varint,11,opt,name=icmp_type" json:"icmp_type,omitempty"`
	IcmpCode   uint32       `protobuf:"varint,12,opt,name=icmp_code" json:"icmp_code,omitempty"`
	RR         []uint32     `protobuf:"varint,13,rep,name=RR" json:"RR,omitempty"`
	Tsonly     []uint32     `protobuf:"varint,14,rep,name=tsonly" json:"tsonly,omitempty"`
	Tsandaddr  []*TsAndAddr `protobuf:"bytes,15,rep,name=tsandaddr" json:"tsandaddr,omitempty"`
}
```


#### func (*PingResponse) Descriptor

```go
func (*PingResponse) Descriptor() ([]byte, []int)
```

#### func (*PingResponse) GetRx

```go
func (m *PingResponse) GetRx() *Time
```

#### func (*PingResponse) GetTsandaddr

```go
func (m *PingResponse) GetTsandaddr() []*TsAndAddr
```

#### func (*PingResponse) GetTx

```go
func (m *PingResponse) GetTx() *Time
```

#### func (*PingResponse) ProtoMessage

```go
func (*PingResponse) ProtoMessage()
```

#### func (*PingResponse) Reset

```go
func (m *PingResponse) Reset()
```

#### func (*PingResponse) String

```go
func (m *PingResponse) String() string
```

#### type PingStats

```go
type PingStats struct {
	Replies int32   `protobuf:"varint,1,opt,name=replies" json:"replies,omitempty"`
	Loss    float32 `protobuf:"fixed32,2,opt,name=loss" json:"loss,omitempty"`
	Min     float32 `protobuf:"fixed32,3,opt,name=min" json:"min,omitempty"`
	Max     float32 `protobuf:"fixed32,4,opt,name=max" json:"max,omitempty"`
	Avg     float32 `protobuf:"fixed32,5,opt,name=avg" json:"avg,omitempty"`
	Stddev  float32 `protobuf:"fixed32,6,opt,name=stddev" json:"stddev,omitempty"`
}
```


#### func (*PingStats) Descriptor

```go
func (*PingStats) Descriptor() ([]byte, []int)
```

#### func (*PingStats) ProtoMessage

```go
func (*PingStats) ProtoMessage()
```

#### func (*PingStats) Reset

```go
func (m *PingStats) Reset()
```

#### func (*PingStats) String

```go
func (m *PingStats) String() string
```

#### type Probe

```go
type Probe struct {
	SpooferIp uint32       `protobuf:"varint,1,opt,name=spoofer_ip" json:"spoofer_ip,omitempty"`
	ProbeId   uint32       `protobuf:"varint,2,opt,name=probe_id" json:"probe_id,omitempty"`
	Src       uint32       `protobuf:"varint,4,opt,name=src" json:"src,omitempty"`
	Dst       uint32       `protobuf:"varint,5,opt,name=dst" json:"dst,omitempty"`
	Id        uint32       `protobuf:"varint,6,opt,name=id" json:"id,omitempty"`
	SeqNum    uint32       `protobuf:"varint,7,opt,name=seq_num" json:"seq_num,omitempty"`
	RR        *RecordRoute `protobuf:"bytes,8,opt,name=r_r" json:"r_r,omitempty"`
	Ts        *TimeStamp   `protobuf:"bytes,9,opt,name=ts" json:"ts,omitempty"`
	SenderIp  uint32       `protobuf:"varint,10,opt,name=sender_ip" json:"sender_ip,omitempty"`
}
```


#### func (*Probe) Descriptor

```go
func (*Probe) Descriptor() ([]byte, []int)
```

#### func (*Probe) GetRR

```go
func (m *Probe) GetRR() *RecordRoute
```

#### func (*Probe) GetTs

```go
func (m *Probe) GetTs() *TimeStamp
```

#### func (*Probe) ProtoMessage

```go
func (*Probe) ProtoMessage()
```

#### func (*Probe) Reset

```go
func (m *Probe) Reset()
```

#### func (*Probe) String

```go
func (m *Probe) String() string
```

#### type RRSpooferRequest

```go
type RRSpooferRequest struct {
	Addr uint32 `protobuf:"varint,1,opt,name=addr" json:"addr,omitempty"`
	Max  uint32 `protobuf:"varint,2,opt,name=max" json:"max,omitempty"`
}
```


#### func (*RRSpooferRequest) Descriptor

```go
func (*RRSpooferRequest) Descriptor() ([]byte, []int)
```

#### func (*RRSpooferRequest) ProtoMessage

```go
func (*RRSpooferRequest) ProtoMessage()
```

#### func (*RRSpooferRequest) Reset

```go
func (m *RRSpooferRequest) Reset()
```

#### func (*RRSpooferRequest) String

```go
func (m *RRSpooferRequest) String() string
```

#### type RRSpooferResponse

```go
type RRSpooferResponse struct {
	Addr     uint32          `protobuf:"varint,1,opt,name=addr" json:"addr,omitempty"`
	Max      uint32          `protobuf:"varint,2,opt,name=max" json:"max,omitempty"`
	Spoofers []*VantagePoint `protobuf:"bytes,3,rep,name=spoofers" json:"spoofers,omitempty"`
}
```


#### func (*RRSpooferResponse) Descriptor

```go
func (*RRSpooferResponse) Descriptor() ([]byte, []int)
```

#### func (*RRSpooferResponse) GetSpoofers

```go
func (m *RRSpooferResponse) GetSpoofers() []*VantagePoint
```

#### func (*RRSpooferResponse) ProtoMessage

```go
func (*RRSpooferResponse) ProtoMessage()
```

#### func (*RRSpooferResponse) Reset

```go
func (m *RRSpooferResponse) Reset()
```

#### func (*RRSpooferResponse) String

```go
func (m *RRSpooferResponse) String() string
```

#### type RTT

```go
type RTT struct {
	Sec  int64 `protobuf:"varint,1,opt,name=sec" json:"sec,omitempty"`
	Usec int64 `protobuf:"varint,2,opt,name=usec" json:"usec,omitempty"`
}
```


#### func (*RTT) Descriptor

```go
func (*RTT) Descriptor() ([]byte, []int)
```

#### func (*RTT) ProtoMessage

```go
func (*RTT) ProtoMessage()
```

#### func (*RTT) Reset

```go
func (m *RTT) Reset()
```

#### func (*RTT) String

```go
func (m *RTT) String() string
```

#### type RecSpoof

```go
type RecSpoof struct {
	Spoofs []*Spoof `protobuf:"bytes,1,rep,name=spoofs" json:"spoofs,omitempty"`
}
```


#### func (*RecSpoof) Descriptor

```go
func (*RecSpoof) Descriptor() ([]byte, []int)
```

#### func (*RecSpoof) GetSpoofs

```go
func (m *RecSpoof) GetSpoofs() []*Spoof
```

#### func (*RecSpoof) ProtoMessage

```go
func (*RecSpoof) ProtoMessage()
```

#### func (*RecSpoof) Reset

```go
func (m *RecSpoof) Reset()
```

#### func (*RecSpoof) String

```go
func (m *RecSpoof) String() string
```

#### type ReceiveSpoofedProbesResponse

```go
type ReceiveSpoofedProbesResponse struct {
}
```


#### func (*ReceiveSpoofedProbesResponse) Descriptor

```go
func (*ReceiveSpoofedProbesResponse) Descriptor() ([]byte, []int)
```

#### func (*ReceiveSpoofedProbesResponse) ProtoMessage

```go
func (*ReceiveSpoofedProbesResponse) ProtoMessage()
```

#### func (*ReceiveSpoofedProbesResponse) Reset

```go
func (m *ReceiveSpoofedProbesResponse) Reset()
```

#### func (*ReceiveSpoofedProbesResponse) String

```go
func (m *ReceiveSpoofedProbesResponse) String() string
```

#### type RecordRoute

```go
type RecordRoute struct {
	Hops []uint32 `protobuf:"varint,1,rep,packed,name=hops" json:"hops,omitempty"`
}
```


#### func (*RecordRoute) Descriptor

```go
func (*RecordRoute) Descriptor() ([]byte, []int)
```

#### func (*RecordRoute) ProtoMessage

```go
func (*RecordRoute) ProtoMessage()
```

#### func (*RecordRoute) Reset

```go
func (m *RecordRoute) Reset()
```

#### func (*RecordRoute) String

```go
func (m *RecordRoute) String() string
```

#### type Spoof

```go
type Spoof struct {
	Ip  uint32 `protobuf:"varint,1,opt,name=ip" json:"ip,omitempty"`
	Id  uint32 `protobuf:"varint,2,opt,name=id" json:"id,omitempty"`
	Sip uint32 `protobuf:"varint,3,opt,name=sip" json:"sip,omitempty"`
	Dst uint32 `protobuf:"varint,4,opt,name=dst" json:"dst,omitempty"`
}
```


#### func (*Spoof) Descriptor

```go
func (*Spoof) Descriptor() ([]byte, []int)
```

#### func (*Spoof) ProtoMessage

```go
func (*Spoof) ProtoMessage()
```

#### func (*Spoof) Reset

```go
func (m *Spoof) Reset()
```

#### func (*Spoof) String

```go
func (m *Spoof) String() string
```

#### type SpoofedProbes

```go
type SpoofedProbes struct {
	Probes []*Probe `protobuf:"bytes,1,rep,name=probes" json:"probes,omitempty"`
}
```


#### func (*SpoofedProbes) Descriptor

```go
func (*SpoofedProbes) Descriptor() ([]byte, []int)
```

#### func (*SpoofedProbes) GetProbes

```go
func (m *SpoofedProbes) GetProbes() []*Probe
```

#### func (*SpoofedProbes) ProtoMessage

```go
func (*SpoofedProbes) ProtoMessage()
```

#### func (*SpoofedProbes) Reset

```go
func (m *SpoofedProbes) Reset()
```

#### func (*SpoofedProbes) String

```go
func (m *SpoofedProbes) String() string
```

#### type SpoofedProbesResponse

```go
type SpoofedProbesResponse struct {
}
```


#### func (*SpoofedProbesResponse) Descriptor

```go
func (*SpoofedProbesResponse) Descriptor() ([]byte, []int)
```

#### func (*SpoofedProbesResponse) ProtoMessage

```go
func (*SpoofedProbesResponse) ProtoMessage()
```

#### func (*SpoofedProbesResponse) Reset

```go
func (m *SpoofedProbesResponse) Reset()
```

#### func (*SpoofedProbesResponse) String

```go
func (m *SpoofedProbesResponse) String() string
```

#### type SrcDst

```go
type SrcDst struct {
	Addr         uint32
	Dst          uint32
	Alias        bool
	Stale        time.Duration
	Src          uint32
	IgnoreSource bool
}
```

SrcDst represents a source destination pair

#### type Stamp

```go
type Stamp struct {
	Time uint32 `protobuf:"varint,1,opt,name=time" json:"time,omitempty"`
	Ip   uint32 `protobuf:"varint,2,opt,name=ip" json:"ip,omitempty"`
}
```


#### func (*Stamp) Descriptor

```go
func (*Stamp) Descriptor() ([]byte, []int)
```

#### func (*Stamp) ProtoMessage

```go
func (*Stamp) ProtoMessage()
```

#### func (*Stamp) Reset

```go
func (m *Stamp) Reset()
```

#### func (*Stamp) String

```go
func (m *Stamp) String() string
```

#### type TSSpooferRequest

```go
type TSSpooferRequest struct {
	Max uint32 `protobuf:"varint,1,opt,name=max" json:"max,omitempty"`
}
```


#### func (*TSSpooferRequest) Descriptor

```go
func (*TSSpooferRequest) Descriptor() ([]byte, []int)
```

#### func (*TSSpooferRequest) ProtoMessage

```go
func (*TSSpooferRequest) ProtoMessage()
```

#### func (*TSSpooferRequest) Reset

```go
func (m *TSSpooferRequest) Reset()
```

#### func (*TSSpooferRequest) String

```go
func (m *TSSpooferRequest) String() string
```

#### type TSSpooferResponse

```go
type TSSpooferResponse struct {
	Max      uint32          `protobuf:"varint,1,opt,name=max" json:"max,omitempty"`
	Spoofers []*VantagePoint `protobuf:"bytes,2,rep,name=spoofers" json:"spoofers,omitempty"`
}
```


#### func (*TSSpooferResponse) Descriptor

```go
func (*TSSpooferResponse) Descriptor() ([]byte, []int)
```

#### func (*TSSpooferResponse) GetSpoofers

```go
func (m *TSSpooferResponse) GetSpoofers() []*VantagePoint
```

#### func (*TSSpooferResponse) ProtoMessage

```go
func (*TSSpooferResponse) ProtoMessage()
```

#### func (*TSSpooferResponse) Reset

```go
func (m *TSSpooferResponse) Reset()
```

#### func (*TSSpooferResponse) String

```go
func (m *TSSpooferResponse) String() string
```

#### type TSType

```go
type TSType int32
```


```go
const (
	TSType_TSOnly    TSType = 0
	TSType_TSAndAddr TSType = 1
	TSType_TSPreSpec TSType = 3
)
```

#### func (TSType) EnumDescriptor

```go
func (TSType) EnumDescriptor() ([]byte, []int)
```

#### func (TSType) String

```go
func (x TSType) String() string
```

#### type TTime

```go
type TTime time.Time
```

TTime is a time that matches the format of the time in a warts traceroute

#### func (TTime) MarshalJSON

```go
func (t TTime) MarshalJSON() ([]byte, error)
```
MarshalJSON satisfies the json packages interface

#### func (TTime) String

```go
func (t TTime) String() string
```

#### func (*TTime) UnmarshalJSON

```go
func (t *TTime) UnmarshalJSON(data []byte) (err error)
```
UnmarshalJSON satisfies the json packages interface

#### type Time

```go
type Time struct {
	Sec  int64 `protobuf:"varint,1,opt,name=sec" json:"sec,omitempty"`
	Usec int64 `protobuf:"varint,2,opt,name=usec" json:"usec,omitempty"`
}
```


#### func (*Time) Descriptor

```go
func (*Time) Descriptor() ([]byte, []int)
```

#### func (*Time) ProtoMessage

```go
func (*Time) ProtoMessage()
```

#### func (*Time) Reset

```go
func (m *Time) Reset()
```

#### func (*Time) String

```go
func (m *Time) String() string
```

#### type TimeStamp

```go
type TimeStamp struct {
	Type   TSType   `protobuf:"varint,1,opt,name=type,enum=datamodel.TSType" json:"type,omitempty"`
	Stamps []*Stamp `protobuf:"bytes,2,rep,name=stamps" json:"stamps,omitempty"`
}
```


#### func (*TimeStamp) Descriptor

```go
func (*TimeStamp) Descriptor() ([]byte, []int)
```

#### func (*TimeStamp) GetStamps

```go
func (m *TimeStamp) GetStamps() []*Stamp
```

#### func (*TimeStamp) ProtoMessage

```go
func (*TimeStamp) ProtoMessage()
```

#### func (*TimeStamp) Reset

```go
func (m *TimeStamp) Reset()
```

#### func (*TimeStamp) String

```go
func (m *TimeStamp) String() string
```

#### type Traceroute

```go
type Traceroute struct {
	Type       string           `protobuf:"bytes,1,opt,name=type" json:"type,omitempty"`
	UserId     uint32           `protobuf:"varint,2,opt,name=user_id" json:"user_id,omitempty"`
	Method     string           `protobuf:"bytes,3,opt,name=method" json:"method,omitempty"`
	Src        uint32           `protobuf:"varint,4,opt,name=src" json:"src,omitempty"`
	Dst        uint32           `protobuf:"varint,5,opt,name=dst" json:"dst,omitempty"`
	Sport      uint32           `protobuf:"varint,6,opt,name=sport" json:"sport,omitempty"`
	Dport      uint32           `protobuf:"varint,7,opt,name=dport" json:"dport,omitempty"`
	StopReason string           `protobuf:"bytes,8,opt,name=stop_reason" json:"stop_reason,omitempty"`
	StopData   uint32           `protobuf:"varint,9,opt,name=stop_data" json:"stop_data,omitempty"`
	Start      *TracerouteTime  `protobuf:"bytes,10,opt,name=start" json:"start,omitempty"`
	HopCount   uint32           `protobuf:"varint,11,opt,name=hop_count" json:"hop_count,omitempty"`
	Attempts   uint32           `protobuf:"varint,12,opt,name=attempts" json:"attempts,omitempty"`
	Hoplimit   uint32           `protobuf:"varint,13,opt,name=hoplimit" json:"hoplimit,omitempty"`
	Firsthop   uint32           `protobuf:"varint,14,opt,name=firsthop" json:"firsthop,omitempty"`
	Wait       uint32           `protobuf:"varint,15,opt,name=wait" json:"wait,omitempty"`
	WaitProbe  uint32           `protobuf:"varint,16,opt,name=wait_probe" json:"wait_probe,omitempty"`
	Tos        uint32           `protobuf:"varint,17,opt,name=tos" json:"tos,omitempty"`
	ProbeSize  uint32           `protobuf:"varint,18,opt,name=probe_size" json:"probe_size,omitempty"`
	Hops       []*TracerouteHop `protobuf:"bytes,19,rep,name=hops" json:"hops,omitempty"`
	Error      string           `protobuf:"bytes,20,opt,name=error" json:"error,omitempty"`
	Version    string           `protobuf:"bytes,21,opt,name=version" json:"version,omitempty"`
	GapLimit   uint32           `protobuf:"varint,22,opt,name=gap_limit" json:"gap_limit,omitempty"`
	Id         int64            `protobuf:"varint,23,opt,name=id" json:"id,omitempty"`
}
```


#### func  ConvertTraceroute

```go
func ConvertTraceroute(in warts.Traceroute) Traceroute
```
ConvertTraceroute converts a warts tr to a tr

#### func (*Traceroute) CMarshal

```go
func (t *Traceroute) CMarshal() []byte
```
CMarshal marshals a traceroute for storing in a cache

#### func (*Traceroute) CUnmarshal

```go
func (t *Traceroute) CUnmarshal(data []byte) error
```
CUnmarshal unmarshals a traceroute which is retrieved from a cache

#### func (*Traceroute) Descriptor

```go
func (*Traceroute) Descriptor() ([]byte, []int)
```

#### func (*Traceroute) ErrorString

```go
func (t *Traceroute) ErrorString() string
```
ErrorString generates an error string for a traceroute which is used to print
error messages in reverse traceroute

#### func (*Traceroute) GetHops

```go
func (m *Traceroute) GetHops() []*TracerouteHop
```

#### func (*Traceroute) GetStart

```go
func (m *Traceroute) GetStart() *TracerouteTime
```

#### func (*Traceroute) Key

```go
func (t *Traceroute) Key() string
```
Key generates a chache key for a Traceroute

#### func (*Traceroute) ProtoMessage

```go
func (*Traceroute) ProtoMessage()
```

#### func (*Traceroute) Reset

```go
func (m *Traceroute) Reset()
```

#### func (*Traceroute) String

```go
func (m *Traceroute) String() string
```

#### type TracerouteArg

```go
type TracerouteArg struct {
	Traceroutes []*TracerouteMeasurement `protobuf:"bytes,1,rep,name=traceroutes" json:"traceroutes,omitempty"`
}
```


#### func (*TracerouteArg) Descriptor

```go
func (*TracerouteArg) Descriptor() ([]byte, []int)
```

#### func (*TracerouteArg) GetTraceroutes

```go
func (m *TracerouteArg) GetTraceroutes() []*TracerouteMeasurement
```

#### func (*TracerouteArg) ProtoMessage

```go
func (*TracerouteArg) ProtoMessage()
```

#### func (*TracerouteArg) Reset

```go
func (m *TracerouteArg) Reset()
```

#### func (*TracerouteArg) String

```go
func (m *TracerouteArg) String() string
```

#### type TracerouteArgResp

```go
type TracerouteArgResp struct {
	Traceroutes []*Traceroute `protobuf:"bytes,1,rep,name=traceroutes" json:"traceroutes,omitempty"`
}
```


#### func (*TracerouteArgResp) Descriptor

```go
func (*TracerouteArgResp) Descriptor() ([]byte, []int)
```

#### func (*TracerouteArgResp) GetTraceroutes

```go
func (m *TracerouteArgResp) GetTraceroutes() []*Traceroute
```

#### func (*TracerouteArgResp) ProtoMessage

```go
func (*TracerouteArgResp) ProtoMessage()
```

#### func (*TracerouteArgResp) Reset

```go
func (m *TracerouteArgResp) Reset()
```

#### func (*TracerouteArgResp) String

```go
func (m *TracerouteArgResp) String() string
```

#### type TracerouteHop

```go
type TracerouteHop struct {
	Addr      uint32 `protobuf:"varint,1,opt,name=addr" json:"addr,omitempty"`
	ProbeTtl  uint32 `protobuf:"varint,2,opt,name=probe_ttl" json:"probe_ttl,omitempty"`
	ProbeId   uint32 `protobuf:"varint,3,opt,name=probe_id" json:"probe_id,omitempty"`
	ProbeSize uint32 `protobuf:"varint,4,opt,name=probe_size" json:"probe_size,omitempty"`
	Rtt       *RTT   `protobuf:"bytes,5,opt,name=rtt" json:"rtt,omitempty"`
	ReplyTtl  uint32 `protobuf:"varint,6,opt,name=reply_ttl" json:"reply_ttl,omitempty"`
	ReplyTos  uint32 `protobuf:"varint,7,opt,name=reply_tos" json:"reply_tos,omitempty"`
	ReplySize uint32 `protobuf:"varint,8,opt,name=reply_size" json:"reply_size,omitempty"`
	ReplyIpid uint32 `protobuf:"varint,9,opt,name=reply_ipid" json:"reply_ipid,omitempty"`
	IcmpType  uint32 `protobuf:"varint,10,opt,name=icmp_type" json:"icmp_type,omitempty"`
	IcmpCode  uint32 `protobuf:"varint,11,opt,name=icmp_code" json:"icmp_code,omitempty"`
	IcmpQTtl  uint32 `protobuf:"varint,12,opt,name=icmp_q_ttl" json:"icmp_q_ttl,omitempty"`
	IcmpQIpl  uint32 `protobuf:"varint,13,opt,name=icmp_q_ipl" json:"icmp_q_ipl,omitempty"`
	IcmpQTos  uint32 `protobuf:"varint,14,opt,name=icmp_q_tos" json:"icmp_q_tos,omitempty"`
}
```


#### func (*TracerouteHop) Descriptor

```go
func (*TracerouteHop) Descriptor() ([]byte, []int)
```

#### func (*TracerouteHop) GetRtt

```go
func (m *TracerouteHop) GetRtt() *RTT
```

#### func (*TracerouteHop) ProtoMessage

```go
func (*TracerouteHop) ProtoMessage()
```

#### func (*TracerouteHop) Reset

```go
func (m *TracerouteHop) Reset()
```

#### func (*TracerouteHop) String

```go
func (m *TracerouteHop) String() string
```

#### type TracerouteMeasurement

```go
type TracerouteMeasurement struct {
	Staleness    int64  `protobuf:"varint,1,opt,name=staleness" json:"staleness,omitempty"`
	Dst          uint32 `protobuf:"varint,3,opt,name=dst" json:"dst,omitempty"`
	Confidence   string `protobuf:"bytes,4,opt,name=confidence" json:"confidence,omitempty"`
	Dport        string `protobuf:"bytes,5,opt,name=dport" json:"dport,omitempty"`
	FirstHop     string `protobuf:"bytes,6,opt,name=first_hop" json:"first_hop,omitempty"`
	GapLimit     string `protobuf:"bytes,7,opt,name=gap_limit" json:"gap_limit,omitempty"`
	GapAction    string `protobuf:"bytes,8,opt,name=gap_action" json:"gap_action,omitempty"`
	MaxTtl       string `protobuf:"bytes,9,opt,name=max_ttl" json:"max_ttl,omitempty"`
	PathDiscov   bool   `protobuf:"varint,10,opt,name=path_discov" json:"path_discov,omitempty"`
	Loops        string `protobuf:"bytes,11,opt,name=loops" json:"loops,omitempty"`
	LoopAction   string `protobuf:"bytes,12,opt,name=loop_action" json:"loop_action,omitempty"`
	Payload      string `protobuf:"bytes,13,opt,name=payload" json:"payload,omitempty"`
	Method       string `protobuf:"bytes,14,opt,name=method" json:"method,omitempty"`
	Attempts     string `protobuf:"bytes,15,opt,name=attempts" json:"attempts,omitempty"`
	SendAll      bool   `protobuf:"varint,16,opt,name=send_all" json:"send_all,omitempty"`
	Sport        string `protobuf:"bytes,17,opt,name=sport" json:"sport,omitempty"`
	Src          uint32 `protobuf:"varint,18,opt,name=src" json:"src,omitempty"`
	Tos          string `protobuf:"bytes,19,opt,name=tos" json:"tos,omitempty"`
	TimeExceeded bool   `protobuf:"varint,20,opt,name=time_exceeded" json:"time_exceeded,omitempty"`
	UserId       string `protobuf:"bytes,21,opt,name=user_id" json:"user_id,omitempty"`
	Wait         string `protobuf:"bytes,22,opt,name=wait" json:"wait,omitempty"`
	WaitProbe    string `protobuf:"bytes,23,opt,name=wait_probe" json:"wait_probe,omitempty"`
	GssEntry     string `protobuf:"bytes,24,opt,name=gss_entry" json:"gss_entry,omitempty"`
	LssName      string `protobuf:"bytes,25,opt,name=lss_name" json:"lss_name,omitempty"`
	Timeout      int64  `protobuf:"varint,26,opt,name=timeout" json:"timeout,omitempty"`
	CheckCache   bool   `protobuf:"varint,27,opt,name=check_cache" json:"check_cache,omitempty"`
	CheckDb      bool   `protobuf:"varint,28,opt,name=check_db" json:"check_db,omitempty"`
}
```


#### func (*TracerouteMeasurement) CMarshal

```go
func (tm *TracerouteMeasurement) CMarshal() []byte
```
CMarshal marshals a traceroute measurement for storing in a cache

#### func (*TracerouteMeasurement) Descriptor

```go
func (*TracerouteMeasurement) Descriptor() ([]byte, []int)
```

#### func (*TracerouteMeasurement) Key

```go
func (tm *TracerouteMeasurement) Key() string
```
Key generates a key for storing a traceroute measurement in a cache

#### func (*TracerouteMeasurement) ProtoMessage

```go
func (*TracerouteMeasurement) ProtoMessage()
```

#### func (*TracerouteMeasurement) Reset

```go
func (m *TracerouteMeasurement) Reset()
```

#### func (*TracerouteMeasurement) String

```go
func (m *TracerouteMeasurement) String() string
```

#### type TracerouteTime

```go
type TracerouteTime struct {
	Sec   int64  `protobuf:"varint,1,opt,name=sec" json:"sec,omitempty"`
	Usec  int64  `protobuf:"varint,2,opt,name=usec" json:"usec,omitempty"`
	Ftime string `protobuf:"bytes,3,opt,name=ftime" json:"ftime,omitempty"`
}
```


#### func (*TracerouteTime) Descriptor

```go
func (*TracerouteTime) Descriptor() ([]byte, []int)
```

#### func (*TracerouteTime) ProtoMessage

```go
func (*TracerouteTime) ProtoMessage()
```

#### func (*TracerouteTime) Reset

```go
func (m *TracerouteTime) Reset()
```

#### func (*TracerouteTime) String

```go
func (m *TracerouteTime) String() string
```

#### type TsAndAddr

```go
type TsAndAddr struct {
	Ip uint32 `protobuf:"varint,1,opt,name=ip" json:"ip,omitempty"`
	Ts uint32 `protobuf:"varint,2,opt,name=ts" json:"ts,omitempty"`
}
```


#### func (*TsAndAddr) Descriptor

```go
func (*TsAndAddr) Descriptor() ([]byte, []int)
```

#### func (*TsAndAddr) ProtoMessage

```go
func (*TsAndAddr) ProtoMessage()
```

#### func (*TsAndAddr) Reset

```go
func (m *TsAndAddr) Reset()
```

#### func (*TsAndAddr) String

```go
func (m *TsAndAddr) String() string
```

#### type UpdateResponse

```go
type UpdateResponse struct {
}
```


#### func (*UpdateResponse) Descriptor

```go
func (*UpdateResponse) Descriptor() ([]byte, []int)
```

#### func (*UpdateResponse) ProtoMessage

```go
func (*UpdateResponse) ProtoMessage()
```

#### func (*UpdateResponse) Reset

```go
func (m *UpdateResponse) Reset()
```

#### func (*UpdateResponse) String

```go
func (m *UpdateResponse) String() string
```

#### type User

```go
type User struct {
	ID    uint32
	Name  string
	EMail string
	Max   uint32
	Delay uint32
	Key   string
}
```

User is a user of the controller api

#### type VPRequest

```go
type VPRequest struct {
}
```


#### func (*VPRequest) Descriptor

```go
func (*VPRequest) Descriptor() ([]byte, []int)
```

#### func (*VPRequest) ProtoMessage

```go
func (*VPRequest) ProtoMessage()
```

#### func (*VPRequest) Reset

```go
func (m *VPRequest) Reset()
```

#### func (*VPRequest) String

```go
func (m *VPRequest) String() string
```

#### type VPReturn

```go
type VPReturn struct {
	Vps []*VantagePoint `protobuf:"bytes,1,rep,name=vps" json:"vps,omitempty"`
}
```


#### func (*VPReturn) Descriptor

```go
func (*VPReturn) Descriptor() ([]byte, []int)
```

#### func (*VPReturn) GetVps

```go
func (m *VPReturn) GetVps() []*VantagePoint
```

#### func (*VPReturn) ProtoMessage

```go
func (*VPReturn) ProtoMessage()
```

#### func (*VPReturn) Reset

```go
func (m *VPReturn) Reset()
```

#### func (*VPReturn) String

```go
func (m *VPReturn) String() string
```

#### type VantagePoint

```go
type VantagePoint struct {
	Hostname     string `protobuf:"bytes,1,opt,name=hostname" json:"hostname,omitempty"`
	Ip           uint32 `protobuf:"varint,2,opt,name=ip" json:"ip,omitempty"`
	Sshable      bool   `protobuf:"varint,3,opt,name=sshable" json:"sshable,omitempty"`
	Timestamp    bool   `protobuf:"varint,4,opt,name=timestamp" json:"timestamp,omitempty"`
	RecordRoute  bool   `protobuf:"varint,5,opt,name=record_route" json:"record_route,omitempty"`
	LastUpdated  int64  `protobuf:"varint,6,opt,name=last_updated" json:"last_updated,omitempty"`
	CanSpoof     bool   `protobuf:"varint,7,opt,name=can_spoof" json:"can_spoof,omitempty"`
	Controller   uint32 `protobuf:"varint,8,opt,name=controller" json:"controller,omitempty"`
	ReceiveSpoof bool   `protobuf:"varint,9,opt,name=receive_spoof" json:"receive_spoof,omitempty"`
	Site         string `protobuf:"bytes,10,opt,name=site" json:"site,omitempty"`
	SpoofChecked int64  `protobuf:"varint,11,opt,name=spoof_checked" json:"spoof_checked,omitempty"`
	Port         uint32 `protobuf:"varint,12,opt,name=port" json:"port,omitempty"`
}
```


#### func (*VantagePoint) Descriptor

```go
func (*VantagePoint) Descriptor() ([]byte, []int)
```

#### func (*VantagePoint) ProtoMessage

```go
func (*VantagePoint) ProtoMessage()
```

#### func (*VantagePoint) Reset

```go
func (m *VantagePoint) Reset()
```

#### func (*VantagePoint) String

```go
func (m *VantagePoint) String() string
```

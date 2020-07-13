package main

import (
	"fmt"
	"github.com/NEU-SNS/revtrvp/log"
	"github.com/NEU-SNS/revtrvp/util"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	dm "github.com/NEU-SNS/revtrvp/datamodel"
	opt "github.com/rhansen2/ipv4optparser"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	// ID is the ICMDPID magic number
	ID = 0xf0f1
	// SEQ is the ICMP seq number magic number
	SEQ = 0xf2f3
)

var (
	dummy           ipv4.ICMPType
	icmpProtocolNum = dummy.Protocol()
)


var (
	// ErrorNotICMPEcho is returned when the probe is not of the right type
	ErrorNotICMPEcho = fmt.Errorf("Received Non ICMP Probe")
	// ErrorNonSpoofedProbe is returned when the probe is not spoofed
	ErrorNonSpoofedProbe = fmt.Errorf("Received ICMP Probe that was not spoofed")
	// ErrorSpoofedProbeNoID is returned when the probe has no ID
	ErrorSpoofedProbeNoID = fmt.Errorf("Received a spoofed probe with no id")
	// ErrorNoSpooferIP is returned when there is no spoofer ip in the packet
	ErrorNoSpooferIP = fmt.Errorf("No spoofer IP found in packet")
	// ErrorFailedToParseOptions is returned when there was an error parsing options
	ErrorFailedToParseOptions = fmt.Errorf("Failed to parse IPv4 options")
	// ErrorFailedToConvertOption is returned when there is an issue converting an option
	ErrorFailedToConvertOption = fmt.Errorf("Failed to convert IPv4 option")
	// ErrorSpooferIP is returned when the spoofer ip is invalid
	ErrorSpooferIP = fmt.Errorf("Failed to convert spoofer ip")
	// ErrorReadError is returned when there is an error reading from the icmp monitoring conn
	ErrorReadError = fmt.Errorf("Failed to read from conn")
)

func makeID(a, b, c, d byte) uint32 {
	var id uint32
	id |= uint32(a) << 24
	id |= uint32(b) << 16
	id |= uint32(c) << 8
	id |= uint32(d)
	return id
}

func makeRecordRoute(rr opt.RecordRouteOption) (dm.RecordRoute, error) {
	rec := dm.RecordRoute{}
	for _, r := range rr.Routes {
		rec.Hops = append(rec.Hops, uint32(r))
	}
	return rec, nil
}

func makeTimestamp(ts opt.TimeStampOption) (dm.TimeStamp, error) {
	time := dm.TimeStamp{}
	time.Type = dm.TSType(ts.Flags)
	for _, st := range ts.Stamps {
		nst := dm.Stamp{Time: uint32(st.Time), Ip: uint32(st.Addr)}
		time.Stamps = append(time.Stamps, &nst)
	}
	return time, nil
}

func getProbe(conn *ipv4.RawConn) (error) {
	// 1500 should be good because we're sending small packets and its the standard MTU

	// 1500 should be good because we're sending small packets and its the standard MTU

	now := time.Now().Format("2006_01_02_15_04")

	// Directory structure is MLab specific, where MLab's Pusher service sends everything to Google Cloud Storage.
	fname := "/var/spool/revtr/traffic/spooflistener_" + now + ".log"
	logf, errf := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if errf != nil {
		log.Error(errf)
	}

	if _, errf := logf.WriteString("Inside getProbe, trying to get a packet\n"); errf != nil {
		log.Error(errf)
	}
	pBuf := make([]byte, 1500)
	probe := &dm.Probe{}
	// Try and get a packet
	header, pload, _, err := conn.ReadFrom(pBuf)
	if err != nil {
		return ErrorReadError
	}
	// Parse the payload for ICMP stuff
	if _, errf := logf.WriteString("Got packet, parsing payload for ICMP stuff\n"); errf != nil {
		log.Error(errf)
	}
	mess, err := icmp.ParseMessage(icmpProtocolNum, pload)
	if err != nil {
		return err
	}
	if echo, ok := mess.Body.(*icmp.Echo); ok {
		if _, errf := logf.WriteString("Checking if ID (" + strconv.Itoa(echo.ID) +  ") and SEQ (" + strconv.Itoa(echo.Seq) + ") are correct values.\n"); errf != nil {
			log.Error(errf)
		}
		if echo.ID != ID || echo.Seq != SEQ {
			return ErrorNonSpoofedProbe
		}

		if len(echo.Data) < 8 {
			return ErrorSpoofedProbeNoID
		}
		// GetIP of spoofer out of packet
		ip := net.IPv4(echo.Data[0],
			echo.Data[1],
			echo.Data[2],
			echo.Data[3])
		if ip == nil {
			return ErrorNoSpooferIP
		}
		if _, errf := logf.WriteString("get IP of spoofer out of packet: " + ip.String() + "\n" ); errf != nil {
			log.Error(errf)
		}

		// Get the Id out of the data
		id := makeID(echo.Data[4], echo.Data[5], echo.Data[6], echo.Data[7])
		probe.ProbeId = id
		probe.SpooferIp, err = util.IPtoInt32(ip)
		if err != nil {
			return ErrorSpooferIP
		}
		probe.Dst, err = util.IPtoInt32(header.Dst)
		probe.Src, err = util.IPtoInt32(header.Src)

		if _, errf := logf.WriteString("Src: "  + header.Src.String() + " and Dst: " + header.Dst.String() + "\n" ); errf != nil {
			log.Error(errf)
		}

		// Parse the options
		options, err := opt.Parse(header.Options)
		if err != nil {
			return ErrorFailedToParseOptions
		}
		probe.SeqNum = uint32(echo.Seq)
		probe.Id = uint32(echo.ID)
		for _, option := range options {
			switch option.Type {
			case opt.RecordRoute:
				if _, errf := logf.WriteString("Case RecordRoute\n"); errf != nil {
					log.Error(errf)
				}

				rr, err := option.ToRecordRoute()
				if err != nil {
					return ErrorFailedToConvertOption
				}
				rec, err := makeRecordRoute(rr)
				if err != nil {
					return ErrorFailedToConvertOption
				}
				probe.RR = &rec
			case opt.InternetTimestamp:
				if _, errf := logf.WriteString("Case Timestamp\n"); errf != nil {
					log.Error(errf)
				}

				ts, err := option.ToTimeStamp()
				if err != nil {
					return ErrorFailedToConvertOption
				}
				nts, err := makeTimestamp(ts)
				if err != nil {
					return ErrorFailedToConvertOption
				}
				probe.Ts = &nts
			}
		}
	}
	return ErrorNotICMPEcho
}

// GetBindAddr gets the IP of the eth0 like address
// (!!MLab specific!!: use net1 because eth0 is private)
func GetBindAddr() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if strings.Contains(iface.Name, "eth0") &&
			uint(iface.Flags)&uint(net.FlagUp) > 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return "", err
			}
			addr := addrs[0]
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return "", err
			}
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("Didn't find net1 interface")
}

func reconnect(addr string) (*ipv4.RawConn, error) {
	pc, err := net.ListenPacket(fmt.Sprintf("ip4:%d", icmpProtocolNum), addr)
	if err != nil {
		return nil, err
	}
	return ipv4.NewRawConn(pc)
}

func main(){
	addr, _ := GetBindAddr()
	fmt.Println("addr is: " + addr)
	c, err := reconnect(addr)
	if err != nil {
		fmt.Println("error")
		return
	}
	for {
		fmt.Println("Listening for a new probe.")
		getProbe(c)
	}
}
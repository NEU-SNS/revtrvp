package spoofmap

import (
	"fmt"
	"sync"
	"time"

	dm "github.com/NEU-SNS/revtr-vp/datamodel"
	"github.com/NEU-SNS/revtr-vp/log"
)

var (
	// ErrorIDInUse is returned when the id of a spoofed request is already in use.
	ErrorIDInUse = fmt.Errorf("The is received is already in use.")
	// ErrorSpoofNotFound is returned when a spoof is received that doesn't have
	// have a matching id
	ErrorSpoofNotFound = fmt.Errorf("Received a spoof with no matching Id")
)

// Sender is the interface for something that can sent a slice of SpoofedProbes
// to an address
type Sender interface {
	Send([]*dm.Probe, uint32) error
}

type spoof struct {
	probe *dm.Probe
	t     time.Time
	spoof dm.Spoof
}

type SpoofMap interface {
	Quit()
	Register(dm.Spoof) error
	Receive(*dm.Probe) error
}

// SpoofMap is used to track spoofed measurement requests
type spoofMap struct {
	sync.Mutex
	spoofs    map[uint32]*spoof
	quit      chan struct{}
	transport Sender
}

// New creates a SpoofMap
func New(s Sender) SpoofMap {
	sm := &spoofMap{
		spoofs:    make(map[uint32]*spoof),
		transport: s,
		quit:      make(chan struct{}),
	}
	go sm.sendSpoofs()
	go sm.cleanOld()
	return sm
}

// Quit ends the sending loop of the spoofMap
func (s *spoofMap) Quit() {
	close(s.quit)
}

// Register is called when a spoof is desired
func (s *spoofMap) Register(sp dm.Spoof) error {
	s.Lock()
	defer s.Unlock()
	if spf, ok := s.spoofs[sp.Id]; ok {
		if time.Since(spf.t) > time.Second*60 {
			s.spoofs[sp.Id] = &spoof{
				t:     time.Now(),
				spoof: sp,
			}
			return nil
		}
		return ErrorIDInUse
	}
	s.spoofs[sp.Id] = &spoof{
		t:     time.Now(),
		spoof: sp,
	}
	return nil
}

// Receive is used when a probe for a spoof is gotten
func (s *spoofMap) Receive(p *dm.Probe) error {
	s.Lock()
	defer s.Unlock()
	if sp, ok := s.spoofs[p.ProbeId]; ok {
		pr := *p
		sp.probe = &pr
		return nil
	}
	return ErrorSpoofNotFound
}

// call in a goroutine
func (s *spoofMap) sendSpoofs() {
	t := time.NewTicker(time.Second * 2)
	var dests map[uint32][]*dm.Probe
	for {
		select {
		case <-s.quit:
			return
		case <-t.C:
			s.Lock()
			dests = make(map[uint32][]*dm.Probe)
			for id, spoof := range s.spoofs {
				if spoof.probe != nil {
					dests[spoof.probe.SenderIp] = append(dests[spoof.probe.SenderIp], spoof.probe)
					spoof.probe = nil
					delete(s.spoofs, id)
				}
			}
			for ip, probes := range dests {
				if err := s.transport.Send(probes, ip); err != nil {
					log.Error(err)
					continue
				}
				delete(dests, ip)
			}
			s.Unlock()
		}
	}
}

// run this in a goroutine
// spoofed probes may never get responses
// clean out old ones so the memory doesn't grow quite as much
func (s *spoofMap) cleanOld() {
	t := time.NewTicker(time.Minute)
	var count int
	for {
		select {
		case <-s.quit:
			return
		case <-t.C:
			s.Lock()
			count = 0
			for id, spoof := range s.spoofs {
				if time.Since(spoof.t) > time.Second*60 {
					spoof.probe = nil
					delete(s.spoofs, id)
				}
				count++
				if count == 10000 {
					break
				}
			}
			s.Unlock()
		}
	}
}

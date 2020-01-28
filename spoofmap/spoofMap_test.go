package spoofmap_test

import (
	"sort"
	"testing"
	"time"

	"github.com/NEU-SNS/revtrvp/datamodel"
	"github.com/NEU-SNS/revtrvp/spoofmap"
	"github.com/NEU-SNS/revtrvp/util"
)

type sender struct {
	sent []*datamodel.Probe
}

func (s *sender) Send(ps []*datamodel.Probe, ip uint32) error {
	s.sent = append(s.sent, ps...)
	return nil
}

func (s *sender) getProbes() []*datamodel.Probe {
	return s.sent
}

func TestQuit(t *testing.T) {
	// just make sure there are no goroutines left behind when Quit is called
	defer util.LeakCheck(t)()
	sm := spoofmap.New(&sender{})
	sm.Quit()
}

func TestRegister(t *testing.T) {
	defer util.LeakCheck(t)()
	sm := spoofmap.New(&sender{})
	defer sm.Quit()
	sp := datamodel.Spoof{
		Id: 1,
	}
	err := sm.Register(sp)
	if err != nil {
		t.Fatalf("Error when Registering a spoof[%v]", sp)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	defer util.LeakCheck(t)()
	sm := spoofmap.New(&sender{})
	defer sm.Quit()
	sp := datamodel.Spoof{
		Id: 1,
	}
	sp2 := datamodel.Spoof{
		Id: 1,
	}
	err := sm.Register(sp)
	if err != nil {
		t.Fatalf("Error when Registering a spoof[%v]", sp)
	}
	err = sm.Register(sp2)
	if err == nil {
		t.Fatalf("Expected error when adding duplicate spoof.")
	}
	if err != spoofmap.ErrorIDInUse {
		t.Fatalf("Expected[%v] got [%v]", spoofmap.ErrorIDInUse, err)
	}
}

func TestReceive(t *testing.T) {
	defer util.LeakCheck(t)()
	for _, test := range []struct {
		add      []datamodel.Spoof
		addErr   error
		rec      []datamodel.Probe
		recError error
	}{
		{nil, nil, []datamodel.Probe{datamodel.Probe{Id: 1}}, spoofmap.ErrorSpoofNotFound},
		{[]datamodel.Spoof{datamodel.Spoof{Id: 1}, datamodel.Spoof{Id: 2}}, nil,
			[]datamodel.Probe{datamodel.Probe{ProbeId: 1}, datamodel.Probe{ProbeId: 2}}, nil,
		},
	} {
		sm := spoofmap.New(&sender{})
		for _, a := range test.add {
			if err := sm.Register(a); err != test.addErr {
				t.Fatalf("Adding probe. execpted[%v], got[%v]", test.addErr, err)
			}
		}
		for _, r := range test.rec {
			if err := sm.Receive(&r); err != test.recError {
				t.Fatalf("Receiving probe. execpted[%v], got[%v]", test.addErr, err)
			}
		}
		sm.Quit()
	}
}

type byProbeID []datamodel.Probe

func (b byProbeID) Len() int           { return len(b) }
func (b byProbeID) Less(i, j int) bool { return b[i].ProbeId < b[j].ProbeId }
func (b byProbeID) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }

type byProbeIDP []*datamodel.Probe

func (b byProbeIDP) Len() int           { return len(b) }
func (b byProbeIDP) Less(i, j int) bool { return b[i].ProbeId < b[j].ProbeId }
func (b byProbeIDP) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }

func TestSendSpoofs(t *testing.T) {
	t.Parallel()
	defer util.LeakCheck(t)()
	for _, test := range []struct {
		add          []datamodel.Spoof
		addErr       error
		rec          []datamodel.Probe
		recError     error
		expectedSent []datamodel.Probe
	}{
		{[]datamodel.Spoof{datamodel.Spoof{Id: 1}, datamodel.Spoof{Id: 2}, datamodel.Spoof{Id: 3}}, nil,
			[]datamodel.Probe{datamodel.Probe{ProbeId: 1}, datamodel.Probe{ProbeId: 2}, datamodel.Probe{ProbeId: 3}}, nil,
			[]datamodel.Probe{datamodel.Probe{ProbeId: 1}, datamodel.Probe{ProbeId: 2}, datamodel.Probe{ProbeId: 3}},
		},
		{[]datamodel.Spoof{datamodel.Spoof{Id: 1}, datamodel.Spoof{Id: 2}, datamodel.Spoof{Id: 3}, datamodel.Spoof{Id: 4}}, nil,
			[]datamodel.Probe{datamodel.Probe{ProbeId: 1}, datamodel.Probe{ProbeId: 2}, datamodel.Probe{ProbeId: 3}}, nil,
			[]datamodel.Probe{datamodel.Probe{ProbeId: 1}, datamodel.Probe{ProbeId: 2}, datamodel.Probe{ProbeId: 3}},
		},
	} {
		s := &sender{}
		sm := spoofmap.New(s)
		for _, a := range test.add {
			if err := sm.Register(a); err != test.addErr {
				t.Fatalf("Adding probe. execpted[%v], got[%v]", test.addErr, err)
			}
		}
		for _, r := range test.rec {
			if err := sm.Receive(&r); err != test.recError {
				t.Fatalf("Receiving probe. execpted[%v], got[%v]", test.addErr, err)
			}
		}
		// Sending happens every 2 seconds
		<-time.After(time.Second * 3)
		pr := s.getProbes()
		if len(pr) != len(test.expectedSent) {
			t.Fatalf("Sending probles, count did not match expected[%d], got[%d]", len(test.expectedSent), len(pr))
		}
		sort.Sort(byProbeID(test.expectedSent))
		sort.Sort(byProbeIDP(pr))
		for i, p := range test.expectedSent {
			if p != *pr[i] {
				t.Fatalf("Sending probes did not match expected[%v], got[%v]\n %v, %v", &p, pr[i], test.expectedSent, pr)
			}
		}
		sm.Quit()
	}
}

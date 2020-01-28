package controller

import (
	"sync"

	dm "github.com/NEU-SNS/revtrvp/datamodel"
	"github.com/prometheus/log"
)

type spoofMap struct {
	sync.Mutex
	sm map[uint32]*channel
}

type channel struct {
	mu    sync.Mutex
	count int
	ch    chan *dm.Probe
	kill  chan struct{}
}

func newChannel(ch chan *dm.Probe, kill chan struct{}, count int) *channel {
	return &channel{
		ch:    ch,
		count: count,
		kill:  kill,
	}
}

func (c *channel) Send(p *dm.Probe) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count--
	select {
	case c.ch <- p:
	case <-c.kill:
		return
	}

	if c.count == 0 {
		close(c.ch)
	}
}

// kill must always be closed when this is done
func (sm *spoofMap) Add(notify chan *dm.Probe, kill chan struct{}, ids []uint32) {
	sm.Lock()
	defer sm.Unlock()
	log.Debugf("Adding spoof IDs: %v", ids)
	ch := newChannel(notify, kill, len(ids))
	for _, id := range ids {
		sm.sm[id] = ch
	}
	// When the group is killed, remove any ids that were left over
	go func() {
		select {
		case <-kill:
			sm.Lock()
			defer sm.Unlock()
			for _, id := range ids {
				delete(sm.sm, id)
			}
		}
	}()
}

func (sm *spoofMap) Notify(probe *dm.Probe) {
	sm.Lock()
	defer sm.Unlock()
	log.Debug("Notify: ", probe)
	if c, ok := sm.sm[probe.ProbeId]; ok {
		c.Send(probe)
		delete(sm.sm, probe.ProbeId)
		return
	}
	log.Errorf("No channel found for probe: %v", probe.ProbeId)
}

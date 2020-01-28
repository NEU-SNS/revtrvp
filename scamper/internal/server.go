package internal

import (
	"io"
	"net"
	"sync"

	"log"
)

type ScamperServer struct {
	l         net.Listener
	addr      string
	responses map[string][]byte
	donec     chan struct{}
	conmu     sync.Mutex
	conns     []io.Closer
}

func NewServer(addr string, respon map[string][]byte) *ScamperServer {
	return &ScamperServer{
		addr:      addr,
		responses: respon,
		donec:     make(chan struct{}),
	}
}

func (s *ScamperServer) Start() error {
	l, err := net.Listen("unix", s.addr)
	if err != nil {
		return err
	}
	s.l = l
	go s.process()
	return nil
}

func (s *ScamperServer) process() {
	for {
		con, err := s.l.Accept()
		if err != nil {
			return
		}
		s.conmu.Lock()
		s.conns = append(s.conns, con)
		s.conmu.Unlock()
		go func(c net.Conn) {
			for {
				var buf [512]byte
				_, err := c.Read(buf[:])
				if err != nil {
					log.Println("Read")
					log.Println(err)
					return
				}
				if resp, ok := s.responses[makeKey(buf[:])]; ok {
					_, err := c.Write(resp)
					if err != nil {
						log.Println("Write")
						log.Println(err)
					}
				}

			}
		}(con)
	}
}

func makeKey(b []byte) string {
	return string(b[:1])
}

func (s *ScamperServer) Stop() error {
	s.CloseConns()
	return s.l.Close()
}

func (s *ScamperServer) CloseConns() {
	s.conmu.Lock()
	defer s.conmu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
}

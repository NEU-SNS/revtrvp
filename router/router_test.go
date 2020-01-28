package router_test

import (
	"path/filepath"
	"testing"

	"github.com/NEU-SNS/revtrvp/router"
)

var (
	rootCA = "../doc/certs/root.crt"
)

type source struct {
	SD router.ServiceDef
}

func (s source) Get(addr string) (router.ServiceDef, error) {
	return s.SD, nil
}

func (s source) All() []router.ServiceDef {
	return []router.ServiceDef{
		s.SD,
	}
}

func TestGetMT(t *testing.T) {
	path, err := filepath.Abs(rootCA)
	if err != nil {
		t.Fatal(err)
	}
	r := router.New(path)
	s := router.ServiceDef{
		Addr:    "plcontroller.revtr.ccs.neu.edu",
		Port:    "4380",
		Service: router.PlanetLab,
	}
	for _, test := range []struct {
		addr  string
		sd    router.ServiceDef
		errs  error
		s     source
		errmt error
		close bool
	}{
		{addr: "any", sd: s, s: source{SD: s}},
		{addr: "any", sd: router.ServiceDef{}, errmt: router.ErrCantCreateMt, s: source{}},
	} {
		r.SetSource(test.s)
		sd, err := r.GetService(test.addr)
		if err != test.errs {
			t.Fatalf("r.GetService(%s), Expected[%v], Got[%v]", test.addr, test.errs, err)
		}
		mt, err := r.GetMT(sd)
		if err != test.errmt {
			t.Fatalf("r.GetMT(%s), Expected[%v], Got[%v]", sd, test.errmt, err)
		}
		if test.close {
			mt.Close()
		}
	}
}

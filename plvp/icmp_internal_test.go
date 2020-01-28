package plvp

import (
	"testing"

	dm "github.com/NEU-SNS/revtrvp/datamodel"
	opt "github.com/rhansen2/ipv4optparser"
)

func uint32SliceEquals(l, r []uint32) bool {
	if len(l) != len(r) {
		return false
	}
	for i, curr := range l {
		if curr != r[i] {
			return false
		}
	}
	return true
}

func TestMakeRecordRoute(t *testing.T) {
	for _, test := range []struct {
		rr   opt.RecordRouteOption
		res  dm.RecordRoute
		werr error
	}{
		{
			rr: opt.RecordRouteOption{
				Type:   opt.RecordRoute,
				Length: opt.OptionLength(0),
				Routes: nil,
			},
			res: dm.RecordRoute{
				Hops: []uint32{},
			},
			werr: nil,
		}, {
			rr: opt.RecordRouteOption{
				Type:   opt.RecordRoute,
				Length: opt.OptionLength(0),
				Routes: []opt.Route{0, 2, 3, 4, 5},
			},
			res: dm.RecordRoute{
				Hops: []uint32{0, 2, 3, 4, 5},
			},
			werr: nil,
		},
	} {
		res, err := makeRecordRoute(test.rr)
		if err != test.werr {
			t.Fatalf("makeRecordRoute(%v) Wanted: %v, %v, Got %v %v", test.rr, test.res, test.werr, res, err)
		}
		if !uint32SliceEquals(test.res.Hops, res.Hops) {
			t.Fatalf("makeRecordRoute(%v) Waited %v got %v", test.rr, test.res, res)
		}
	}
}

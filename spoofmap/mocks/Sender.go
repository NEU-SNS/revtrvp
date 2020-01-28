package mocks

import "github.com/stretchr/testify/mock"

import dm "github.com/NEU-SNS/revtr-vp/datamodel"

type Sender struct {
	mock.Mock
}

// Send provides a mock function with given fields: _a0, _a1
func (_m *Sender) Send(_a0 []*dm.Probe, _a1 uint32) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func([]*dm.Probe, uint32) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

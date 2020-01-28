package mocks

import "github.com/stretchr/testify/mock"

import dm "github.com/NEU-SNS/revtr-vp/datamodel"

type SpoofMap struct {
	mock.Mock
}

// Quit provides a mock function with given fields:
func (_m *SpoofMap) Quit() {
	_m.Called()
}

// Register provides a mock function with given fields: _a0
func (_m *SpoofMap) Register(_a0 dm.Spoof) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(dm.Spoof) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Receive provides a mock function with given fields: _a0
func (_m *SpoofMap) Receive(_a0 *dm.Probe) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*dm.Probe) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

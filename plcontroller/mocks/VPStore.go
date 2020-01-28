package mocks

import "github.com/stretchr/testify/mock"

import dm "github.com/NEU-SNS/revtr-vp/datamodel"

type VPStore struct {
	mock.Mock
}

// UpdateController provides a mock function with given fields: _a0, _a1, _a2
func (_m *VPStore) UpdateController(_a0 uint32, _a1 uint32, _a2 uint32) error {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 error
	if rf, ok := ret.Get(0).(func(uint32, uint32, uint32) error); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetVPs provides a mock function with given fields:
func (_m *VPStore) GetVPs() ([]*dm.VantagePoint, error) {
	ret := _m.Called()

	var r0 []*dm.VantagePoint
	if rf, ok := ret.Get(0).(func() []*dm.VantagePoint); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*dm.VantagePoint)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetActiveVPs provides a mock function with given fields:
func (_m *VPStore) GetActiveVPs() ([]*dm.VantagePoint, error) {
	ret := _m.Called()

	var r0 []*dm.VantagePoint
	if rf, ok := ret.Get(0).(func() []*dm.VantagePoint); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*dm.VantagePoint)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateCheckStatus provides a mock function with given fields: _a0, _a1
func (_m *VPStore) UpdateCheckStatus(_a0 uint32, _a1 string) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(uint32, string) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Close provides a mock function with given fields:
func (_m *VPStore) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

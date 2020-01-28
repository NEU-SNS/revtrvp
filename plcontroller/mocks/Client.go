package mocks

import "github.com/stretchr/testify/mock"

import "github.com/NEU-SNS/revtr-vp/scamper"

type Client struct {
	mock.Mock
}

// AddSocket provides a mock function with given fields: _a0
func (_m *Client) AddSocket(_a0 *scamper.Socket) {
	_m.Called(_a0)
}

// RemoveSocket provides a mock function with given fields: _a0
func (_m *Client) RemoveSocket(_a0 string) {
	_m.Called(_a0)
}

// GetSocket provides a mock function with given fields: _a0
func (_m *Client) GetSocket(_a0 string) (*scamper.Socket, error) {
	ret := _m.Called(_a0)

	var r0 *scamper.Socket
	if rf, ok := ret.Get(0).(func(string) *scamper.Socket); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*scamper.Socket)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveMeasurement provides a mock function with given fields: _a0, _a1
func (_m *Client) RemoveMeasurement(_a0 string, _a1 uint32) error {
	ret := _m.Called(_a0, _a1)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, uint32) error); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DoMeasurement provides a mock function with given fields: _a0, _a1
func (_m *Client) DoMeasurement(_a0 string, _a1 interface{}) (<-chan scamper.Response, uint32, error) {
	ret := _m.Called(_a0, _a1)

	var r0 <-chan scamper.Response
	if rf, ok := ret.Get(0).(func(string, interface{}) <-chan scamper.Response); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan scamper.Response)
		}
	}

	var r1 uint32
	if rf, ok := ret.Get(1).(func(string, interface{}) uint32); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Get(1).(uint32)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(string, interface{}) error); ok {
		r2 = rf(_a0, _a1)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetAllSockets provides a mock function with given fields:
func (_m *Client) GetAllSockets() <-chan *scamper.Socket {
	ret := _m.Called()

	var r0 <-chan *scamper.Socket
	if rf, ok := ret.Get(0).(func() <-chan *scamper.Socket); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(<-chan *scamper.Socket)
		}
	}

	return r0
}

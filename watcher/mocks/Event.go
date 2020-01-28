package mocks

import "github.com/NEU-SNS/revtrvp/watcher"
import "github.com/stretchr/testify/mock"

type Event struct {
	mock.Mock
}

// Name provides a mock function with given fields:
func (_m *Event) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Type provides a mock function with given fields:
func (_m *Event) Type() watcher.EventType {
	ret := _m.Called()

	var r0 watcher.EventType
	if rf, ok := ret.Get(0).(func() watcher.EventType); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(watcher.EventType)
	}

	return r0
}

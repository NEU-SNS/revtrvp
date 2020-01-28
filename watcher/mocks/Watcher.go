package mocks

import "github.com/NEU-SNS/revtrvp/watcher"
import "github.com/stretchr/testify/mock"

type Watcher struct {
	mock.Mock
}

// Close provides a mock function with given fields:
func (_m *Watcher) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetEvent provides a mock function with given fields:
func (_m *Watcher) GetEvent() (watcher.Event, error) {
	ret := _m.Called()

	var r0 watcher.Event
	if rf, ok := ret.Get(0).(func() watcher.Event); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(watcher.Event)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

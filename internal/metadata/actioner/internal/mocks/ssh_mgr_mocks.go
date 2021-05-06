// Code generated by MockGen. DO NOT EDIT.
// Source: internal/metadata/actioner/dotty_keys_actioner.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	sysaccess "github.com/digitalocean/droplet-agent/internal/sysaccess"
	gomock "github.com/golang/mock/gomock"
)

// MocksshManager is a mock of sshManager interface
type MocksshManager struct {
	ctrl     *gomock.Controller
	recorder *MocksshManagerMockRecorder
}

// MocksshManagerMockRecorder is the mock recorder for MocksshManager
type MocksshManagerMockRecorder struct {
	mock *MocksshManager
}

// NewMocksshManager creates a new mock instance
func NewMocksshManager(ctrl *gomock.Controller) *MocksshManager {
	mock := &MocksshManager{ctrl: ctrl}
	mock.recorder = &MocksshManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MocksshManager) EXPECT() *MocksshManagerMockRecorder {
	return m.recorder
}

// UpdateKeys mocks base method
func (m *MocksshManager) UpdateKeys(keys []*sysaccess.SSHKey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateKeys", keys)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateKeys indicates an expected call of UpdateKeys
func (mr *MocksshManagerMockRecorder) UpdateKeys(keys interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateKeys", reflect.TypeOf((*MocksshManager)(nil).UpdateKeys), keys)
}

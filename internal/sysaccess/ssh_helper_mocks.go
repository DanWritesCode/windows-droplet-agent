// Code generated by MockGen. DO NOT EDIT.
// Source: internal/sysaccess/ssh_helper.go

// Package sysaccess is a generated GoMock package.
package sysaccess

import (
	reflect "reflect"

	sysutil "github.com/digitalocean/dotty-agent/internal/sysutil"
	gomock "github.com/golang/mock/gomock"
)

// MocksshHelper is a mock of sshHelper interface
type MocksshHelper struct {
	ctrl     *gomock.Controller
	recorder *MocksshHelperMockRecorder
}

// MocksshHelperMockRecorder is the mock recorder for MocksshHelper
type MocksshHelperMockRecorder struct {
	mock *MocksshHelper
}

// NewMocksshHelper creates a new mock instance
func NewMocksshHelper(ctrl *gomock.Controller) *MocksshHelper {
	mock := &MocksshHelper{ctrl: ctrl}
	mock.recorder = &MocksshHelperMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MocksshHelper) EXPECT() *MocksshHelperMockRecorder {
	return m.recorder
}

// sshdConfigFile mocks base method
func (m *MocksshHelper) sshdConfigFile() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "sshdConfigFile")
	ret0, _ := ret[0].(string)
	return ret0
}

// sshdConfigFile indicates an expected call of sshdConfigFile
func (mr *MocksshHelperMockRecorder) sshdConfigFile() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "sshdConfigFile", reflect.TypeOf((*MocksshHelper)(nil).sshdConfigFile))
}

// authorizedKeysFile mocks base method
func (m *MocksshHelper) authorizedKeysFile(user *sysutil.User) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "authorizedKeysFile", user)
	ret0, _ := ret[0].(string)
	return ret0
}

// authorizedKeysFile indicates an expected call of authorizedKeysFile
func (mr *MocksshHelperMockRecorder) authorizedKeysFile(user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "authorizedKeysFile", reflect.TypeOf((*MocksshHelper)(nil).authorizedKeysFile), user)
}

// prepareAuthorizedKeys mocks base method
func (m *MocksshHelper) prepareAuthorizedKeys(localKeys []string, dottyKeys []*SSHKey) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "prepareAuthorizedKeys", localKeys, dottyKeys)
	ret0, _ := ret[0].([]string)
	return ret0
}

// prepareAuthorizedKeys indicates an expected call of prepareAuthorizedKeys
func (mr *MocksshHelperMockRecorder) prepareAuthorizedKeys(localKeys, dottyKeys interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "prepareAuthorizedKeys", reflect.TypeOf((*MocksshHelper)(nil).prepareAuthorizedKeys), localKeys, dottyKeys)
}

// removeExpiredKeys mocks base method
func (m *MocksshHelper) removeExpiredKeys(originalKeys map[string][]*SSHKey) map[string][]*SSHKey {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "removeExpiredKeys", originalKeys)
	ret0, _ := ret[0].(map[string][]*SSHKey)
	return ret0
}

// removeExpiredKeys indicates an expected call of removeExpiredKeys
func (mr *MocksshHelperMockRecorder) removeExpiredKeys(originalKeys interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "removeExpiredKeys", reflect.TypeOf((*MocksshHelper)(nil).removeExpiredKeys), originalKeys)
}

// areSameKeys mocks base method
func (m *MocksshHelper) areSameKeys(keys1, keys2 []*SSHKey) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "areSameKeys", keys1, keys2)
	ret0, _ := ret[0].(bool)
	return ret0
}

// areSameKeys indicates an expected call of areSameKeys
func (mr *MocksshHelperMockRecorder) areSameKeys(keys1, keys2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "areSameKeys", reflect.TypeOf((*MocksshHelper)(nil).areSameKeys), keys1, keys2)
}

// validateKey mocks base method
func (m *MocksshHelper) validateKey(k *SSHKey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "validateKey", k)
	ret0, _ := ret[0].(error)
	return ret0
}

// validateKey indicates an expected call of validateKey
func (mr *MocksshHelperMockRecorder) validateKey(k interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "validateKey", reflect.TypeOf((*MocksshHelper)(nil).validateKey), k)
}

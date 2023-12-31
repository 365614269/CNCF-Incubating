// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cubefs/cubefs/blobstore/common/recordlog (interfaces: Encoder)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockRecordLogEncoder is a mock of Encoder interface.
type MockRecordLogEncoder struct {
	ctrl     *gomock.Controller
	recorder *MockRecordLogEncoderMockRecorder
}

// MockRecordLogEncoderMockRecorder is the mock recorder for MockRecordLogEncoder.
type MockRecordLogEncoderMockRecorder struct {
	mock *MockRecordLogEncoder
}

// NewMockRecordLogEncoder creates a new mock instance.
func NewMockRecordLogEncoder(ctrl *gomock.Controller) *MockRecordLogEncoder {
	mock := &MockRecordLogEncoder{ctrl: ctrl}
	mock.recorder = &MockRecordLogEncoderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRecordLogEncoder) EXPECT() *MockRecordLogEncoderMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRecordLogEncoder) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockRecordLogEncoderMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRecordLogEncoder)(nil).Close))
}

// Encode mocks base method.
func (m *MockRecordLogEncoder) Encode(arg0 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Encode", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Encode indicates an expected call of Encode.
func (mr *MockRecordLogEncoderMockRecorder) Encode(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encode", reflect.TypeOf((*MockRecordLogEncoder)(nil).Encode), arg0)
}

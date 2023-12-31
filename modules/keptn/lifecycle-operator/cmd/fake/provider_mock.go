// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package fake

import (
	"sync"

	"k8s.io/client-go/rest"
)

// MockProvider is a mock implementation of config.Provider.
//
//	func TestSomethingThatUsesProvider(t *testing.T) {
//
//		// make and configure a mocked config.Provider
//		mockedProvider := &MockProvider{
//			GetConfigFunc: func() (*rest.Config, error) {
//				panic("mock out the GetConfig method")
//			},
//		}
//
//		// use mockedProvider in code that requires config.Provider
//		// and then make assertions.
//
//	}
type MockProvider struct {
	// GetConfigFunc mocks the GetConfig method.
	GetConfigFunc func() (*rest.Config, error)

	// calls tracks calls to the methods.
	calls struct {
		// GetConfig holds details about calls to the GetConfig method.
		GetConfig []struct {
		}
	}
	lockGetConfig sync.RWMutex
}

// GetConfig calls GetConfigFunc.
func (mock *MockProvider) GetConfig() (*rest.Config, error) {
	if mock.GetConfigFunc == nil {
		panic("MockProvider.GetConfigFunc: method is nil but Provider.GetConfig was just called")
	}
	callInfo := struct {
	}{}
	mock.lockGetConfig.Lock()
	mock.calls.GetConfig = append(mock.calls.GetConfig, callInfo)
	mock.lockGetConfig.Unlock()
	return mock.GetConfigFunc()
}

// GetConfigCalls gets all the calls that were made to GetConfig.
// Check the length with:
//
//	len(mockedProvider.GetConfigCalls())
func (mock *MockProvider) GetConfigCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockGetConfig.RLock()
	calls = mock.calls.GetConfig
	mock.lockGetConfig.RUnlock()
	return calls
}

// Copyright 2023 The CubeFS Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package storage_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/cubefs/cubefs/storage"
	"github.com/cubefs/cubefs/util"
	"github.com/stretchr/testify/require"
)

const testTinyExtentID = 1

const testNormalExtentID = 65

func getTestExtentName(id uint64) (name string, err error) {
	tmp, err := os.MkdirTemp("", "")
	if err != nil {
		return
	}
	name = fmt.Sprintf("%v/%v", tmp, id)
	return
}

func getTestTinyExtentName() (name string, err error) {
	return getTestExtentName(testTinyExtentID)
}

func getTestNormalExtentName() (name string, err error) {
	return getTestExtentName(testNormalExtentID)
}

func mockCrcPersist(t *testing.T, e *storage.Extent, blockNo int, blockCrc uint32) (err error) {
	t.Logf("persist crc extent blockNo: %v blockCrc:%v", blockNo, blockCrc)
	return
}

func getMockCrcPersist(t *testing.T) storage.UpdateCrcFunc {
	return func(e *storage.Extent, blockNo int, crc uint32) (err error) {
		return mockCrcPersist(t, e, blockNo, crc)
	}
}

func normalExtentRwTest(t *testing.T, e *storage.Extent) {
	dataStr := "hello world"
	data := []byte(dataStr)
	// append write
	_, err := e.Write(data, 0, int64(len(data)), 0, storage.AppendWriteType, true, getMockCrcPersist(t), nil)
	require.NoError(t, err)
	require.EqualValues(t, e.Size(), len(data))
	_, err = e.Read(data, 0, int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
	// failed append write
	_, err = e.Write(data, 0, int64(len(data)), 0, storage.AppendWriteType, true, getMockCrcPersist(t), nil)
	require.Error(t, err)
	// random append write
	oldSize := e.Size()
	_, err = e.Write(data, 0, int64(len(data)), 0, storage.RandomWriteType, true, getMockCrcPersist(t), nil)
	require.NoError(t, err)
	require.Equal(t, e.Size(), oldSize)
	_, err = e.Read(data, 0, int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
	// TODO: append random write test
}

func tinyExtentRwTest(t *testing.T, e *storage.Extent) {
	dataStr := "hello world"
	data := []byte(dataStr)
	// append write
	_, err := e.Write(data, 0, int64(len(data)), 0, storage.AppendWriteType, true, getMockCrcPersist(t), nil)
	require.NoError(t, err)
	require.EqualValues(t, e.Size()%util.PageSize, 0)
	_, err = e.Read(data, 0, int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
	// failed append write
	_, err = e.Write(data, 0, int64(len(data)), 0, storage.AppendWriteType, true, getMockCrcPersist(t), nil)
	require.Error(t, err)
	// random write
	oldSize := e.Size()
	_, err = e.Write(data, int64(len(data)), int64(len(data)), 0, storage.RandomWriteType, true, getMockCrcPersist(t), nil)
	require.NoError(t, err)
	require.Equal(t, e.Size(), oldSize)
	_, err = e.Read(data, int64(len(data)), int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
}

func normalExtentCreateTest(t *testing.T, name string) {
	e := storage.NewExtentInCore(name, testNormalExtentID)
	err := e.InitToFS()
	require.NoError(t, err)
	defer e.Close()
	normalExtentRwTest(t, e)
}

func tinyExtentCreateTest(t *testing.T, name string) {
	e := storage.NewExtentInCore(name, testTinyExtentID)
	err := e.InitToFS()
	require.NoError(t, err)
	defer e.Close()
	tinyExtentRwTest(t, e)
}

func normalExtentRecoveryTest(t *testing.T, name string) {
	e := storage.NewExtentInCore(name, testNormalExtentID)
	require.Equal(t, e.Exist(), true)
	err := e.RestoreFromFS()
	require.NoError(t, err)
	defer e.Close()
	dataStr := "hello world"
	data := []byte(dataStr)
	_, err = e.ReadTiny(data, 0, int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
}

func tinyExtentRecoveryTest(t *testing.T, name string) {
	e := storage.NewExtentInCore(name, testTinyExtentID)
	require.Equal(t, e.Exist(), true)
	err := e.RestoreFromFS()
	require.NoError(t, err)
	defer e.Close()
	dataStr := "hello world"
	data := []byte(dataStr)
	_, err = e.ReadTiny(data, 0, int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
	_, err = e.Read(data, int64(len(data)), int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
}

func tinyExtentRepairTest(t *testing.T, name string) {
	e := storage.NewExtentInCore(name, testTinyExtentID)
	require.Equal(t, e.Exist(), true)
	err := e.RestoreFromFS()
	require.NoError(t, err)
	defer e.Close()
	dataStr := "hello world"
	data := []byte(dataStr)
	size := e.Size()
	err = e.TinyExtentRecover(nil, size, int64(len(data)), 0, true)
	require.NoError(t, err)
	t.Logf("extent data size is %v", e.Size())
	_, err = e.Read(data, size, int64(len(data)), true)
	require.NoError(t, err)
	for _, v := range data {
		require.EqualValues(t, v, 0)
	}
	size = e.Size()
	data = []byte(dataStr)
	err = e.TinyExtentRecover(data, size, int64(len(data)), 0, false)
	require.NoError(t, err)
	_, err = e.Read(data, size, int64(len(data)), false)
	require.NoError(t, err)
	require.Equal(t, string(data), dataStr)
}

func TestTinyExtent(t *testing.T) {
	name, err := getTestTinyExtentName()
	if err != nil {
		t.Errorf("failed to get extent path")
		return
	}
	tinyExtentCreateTest(t, name)
	tinyExtentRecoveryTest(t, name)
	tinyExtentRepairTest(t, name)
}

func TestNormalExtent(t *testing.T) {
	name, err := getTestNormalExtentName()
	if err != nil {
		t.Errorf("failed to get extent path")
		return
	}
	normalExtentCreateTest(t, name)
	normalExtentRecoveryTest(t, name)
}

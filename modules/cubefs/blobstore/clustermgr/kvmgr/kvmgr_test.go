// Copyright 2022 The CubeFS Authors.
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

package kvmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cubefs/cubefs/blobstore/api/clustermgr"
	"github.com/cubefs/cubefs/blobstore/clustermgr/base"
	"github.com/cubefs/cubefs/blobstore/clustermgr/persistence/kvdb"
	"github.com/cubefs/cubefs/blobstore/common/trace"
	_ "github.com/cubefs/cubefs/blobstore/testing/nolog"
)

func TestNewKvMgr(t *testing.T) {
	tmpKvDBPath := "/tmp/tmpKvDBPath" + strconv.Itoa(rand.Intn(1000000000))
	defer os.RemoveAll(tmpKvDBPath)

	kvDB, _ := kvdb.Open(tmpKvDBPath, false)
	kvMgr, err := NewKvMgr(kvDB)
	require.NoError(t, err)

	for i := 1; i <= 10; i++ {
		for j := 1; j <= 100; j++ {
			uuidStr := fmt.Sprintf("taskUuid%d", j)
			kvMgr.Set(fmt.Sprintf("repair-%d-%d-%s", i, j, uuidStr), []byte(fmt.Sprintf("repair-task-id-%d-%d", i, j)))
			kvMgr.Set(fmt.Sprintf("balance-%d-%d-%s", i, j, uuidStr), []byte(fmt.Sprintf("balance-task-id-%d-%d", i, j)))
		}
	}

	{
		repairTask, err := kvMgr.Get("repair-1-1-taskUuid1")
		require.NoError(t, err)
		require.Equal(t, repairTask, []byte("repair-task-id-1-1"))

		_, err = kvMgr.Get("not-exist-key")
		require.Error(t, err)
	}

	{
		listRet, err := kvMgr.List(nil)
		require.NoError(t, err)
		require.Nil(t, listRet)

		listRet, err = kvMgr.List(&clustermgr.ListKvOpts{
			Prefix: "",
			Marker: "",
			Count:  0,
		})
		require.NoError(t, err)
		require.Equal(t, len(listRet.Kvs), 10)

		listRet, err = kvMgr.List(&clustermgr.ListKvOpts{Prefix: "repair-1-", Count: 200})
		require.NoError(t, err)
		require.Equal(t, len(listRet.Kvs), 100)

		listRet, err = kvMgr.List(&clustermgr.ListKvOpts{Prefix: "repair-1-", Marker: "repair-1-98-taskUuid98", Count: 100})
		require.NoError(t, err)
		require.Equal(t, len(listRet.Kvs), 1)

		listRet, err = kvMgr.List(&clustermgr.ListKvOpts{Prefix: "repair-1-41-", Marker: "repair-1-40-taskUuid40", Count: 100})
		require.NoError(t, err)
		require.Equal(t, len(listRet.Kvs), 1)

	}

	{
		err := kvMgr.Delete("repair-1-1-taskUuid1")
		require.NoError(t, err)
		repairTask, err := kvMgr.Get("repair-task-id-1-1")
		require.Error(t, err)
		require.Nil(t, repairTask)
	}
}

func TestKvMgr_Apply(t *testing.T) {
	tmpKvDBPath := "/tmp/tmpKvDBPath" + strconv.Itoa(rand.Intn(1000000000))
	defer os.RemoveAll(tmpKvDBPath)

	kvDB, _ := kvdb.Open(tmpKvDBPath, false)
	kvMgr, err := NewKvMgr(kvDB)
	require.NoError(t, err)

	span, ctx := trace.StartSpanFromContext(context.Background(), "")
	kvMgr.LoadData(ctx)
	kvMgr.GetModuleName()
	kvMgr.SetModuleName("")
	kvMgr.NotifyLeaderChange(ctx, 1, "")

	// OperTypeSetKv
	{
		operTypes := make([]int32, 0)
		datas := make([][]byte, 0)

		for i := 1; i <= 10; i++ {
			data, err := json.Marshal(&clustermgr.SetKvArgs{
				Key:   fmt.Sprintf("repair-%d-%d", i, i),
				Value: []byte(fmt.Sprintf("repair-%d-%d-value", i, i)),
			})
			require.NoError(t, err)
			datas = append(datas, data)
			operTypes = append(operTypes, OperTypeSetKv)
		}
		err = kvMgr.Apply(ctx, operTypes, datas, nil)
		require.NoError(t, err)

		val, err := kvMgr.Get("repair-1-1")
		require.NoError(t, err)
		require.Equal(t, val, []byte("repair-1-1-value"))
	}

	// OperTypeDeleteKv
	{
		operTypes := make([]int32, 0)
		datas := make([][]byte, 0)
		for i := 1; i <= 3; i++ {
			data, err := json.Marshal(&clustermgr.DeleteKvArgs{
				Key: fmt.Sprintf("repair-%d-%d", i, i),
			})
			require.NoError(t, err)
			datas = append(datas, data)
			operTypes = append(operTypes, OperTypeDeleteKv)
		}
		err = kvMgr.Apply(ctx, operTypes, datas, nil)
		require.NoError(t, err)
		_, err := kvMgr.Get("repair-1-1")
		require.Error(t, err)

		ret, err := kvMgr.List(&clustermgr.ListKvOpts{
			Prefix: "",
			Marker: "",
			Count:  10,
		})
		require.NoError(t, err)
		require.Equal(t, len(ret.Kvs), 7)
	}

	// concurrency set and delete
	{
		count := 100
		operTypes := make([]int32, 0)
		datas := make([][]byte, 0)
		for i := 1; i <= count; i++ {
			setData, _ := json.Marshal(&clustermgr.SetKvArgs{
				Key:   fmt.Sprintf("repair-%d-%d", i, i),
				Value: []byte(fmt.Sprintf("repair-%d-%d-value", i, i)),
			})
			datas = append(datas, setData)
			operTypes = append(operTypes, OperTypeSetKv)

			deleteData, _ := json.Marshal(&clustermgr.DeleteKvArgs{
				Key: fmt.Sprintf("repair-%d-%d", i, i),
			})
			datas = append(datas, deleteData)
			operTypes = append(operTypes, OperTypeDeleteKv)
		}
		err = kvMgr.Apply(ctx, operTypes, datas, nil)
		require.NoError(t, err)

		// must ensure all key delete success
		for i := 1; i <= count; i++ {
			_, err := kvMgr.Get(fmt.Sprintf("repair-%d-%d", i, i))
			require.Error(t, err)
		}

	}

	// error type or data
	{
		data, _ := json.Marshal(&clustermgr.SetKvArgs{
			Key:   "error-key",
			Value: []byte("error-value"),
		})
		errTestCase := []struct {
			operTypes []int32
			ctxs      []base.ProposeContext
			datas     [][]byte
		}{
			{
				operTypes: []int32{3},
				ctxs:      []base.ProposeContext{{ReqID: span.TraceID()}},
				datas:     [][]byte{data},
			},
			{
				operTypes: []int32{OperTypeSetKv},
				ctxs:      []base.ProposeContext{{ReqID: span.TraceID()}},
				datas:     [][]byte{data[:len(data)-1]},
			},
			{
				operTypes: []int32{OperTypeDeleteKv},
				ctxs:      []base.ProposeContext{{ReqID: span.TraceID()}},
				datas:     [][]byte{data[:len(data)-1]},
			},
		}

		for _, tCase := range errTestCase {
			err = kvMgr.Apply(ctx, tCase.operTypes, tCase.datas, tCase.ctxs)
			require.Error(t, err)
		}

	}
}

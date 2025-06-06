// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/go-openapi/runtime/middleware"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

type GetNodesSuite struct {
	nm NodeManager
}

var fakeConfig = &option.DaemonConfig{
	RoutingMode: option.RoutingModeTunnel,
	EnableIPSec: true,
	EncryptNode: true,
}

func setupGetNodesSuite(tb testing.TB) *GetNodesSuite {
	logger := hivetest.Logger(tb)
	option.Config.IPv4ServiceRange = "auto"
	option.Config.IPv6ServiceRange = "auto"

	h, _ := cell.NewSimpleHealth()
	nm, err := New(logger, fakeConfig, tunnel.Config{}, nil, &fakeTypes.IPSet{}, nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(tb, err)

	g := &GetNodesSuite{
		nm: nm,
	}
	return g
}

func Test_getNodesHandle(t *testing.T) {
	g := setupGetNodesSuite(t)
	// Set seed so we can have the same pseudorandom client IDs.
	// The seed is set to 0 for each unit test.
	randSrc.Seed(0, 0)
	const numberOfClients = 10

	clientIDs := make([]int64, 0, numberOfClients)
	for range numberOfClients {
		clientIDs = append(clientIDs, randGen.Int64())
	}

	var zero int64
	type args struct {
		params      GetClusterNodesParams
		clients     map[int64]*clusterNodesClient
		nodeManager NodeManager
	}
	type want struct {
		clients   map[int64]*clusterNodesClient
		responder *GetClusterNodesOK
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() want
	}{
		{
			name: "create a client ID and store it locally",
			setupArgs: func() args {
				return args{
					params: GetClusterNodesParams{
						ClientID: &zero,
					},
					nodeManager: g.nm,
					clients:     map[int64]*clusterNodesClient{},
				}
			},
			setupWanted: func() want {
				m := &models.ClusterNodeStatus{
					ClientID: clientIDs[0],
					Self:     nodeTypes.GetAbsoluteNodeName(),
				}
				return want{
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: m,
						},
					},
					responder: &GetClusterNodesOK{
						Payload: m,
					},
				}
			},
		},
		{
			name: "retrieve nodes diff from a client that was already present",
			setupArgs: func() args {
				return args{
					params: GetClusterNodesParams{
						ClientID: &clientIDs[0],
					},
					nodeManager: g.nm,
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					// let's not forget once the server sends the diff to the
					// client, the slice of nodes added and removed gets cleaned
					// up
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     nodeTypes.GetAbsoluteNodeName(),
							NodesAdded: []*models.NodeElement{
								{
									Name: "random-node-added",
								},
							},
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes from an expired client, it should be ok because the clean up only happens when on insertion",
			setupArgs: func() args {
				return args{
					params: GetClusterNodesParams{
						ClientID: &clientIDs[0],
					},
					nodeManager: g.nm,
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							lastSync: time.Now().Add(-clientGCTimeout),
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					// let's not forget once the server sends the diff to the
					// client, the slice of nodes added and removed gets cleaned
					// up
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     nodeTypes.GetAbsoluteNodeName(),
							NodesAdded: []*models.NodeElement{
								{
									Name: "random-node-added",
								},
							},
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a new client, the expired client should be deleted",
			setupArgs: func() args {
				return args{
					params: GetClusterNodesParams{
						ClientID: &zero,
					},
					nodeManager: g.nm,
					clients: map[int64]*clusterNodesClient{
						clientIDs[numberOfClients-1]: {
							lastSync: time.Now().Add(-clientGCTimeout),
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[numberOfClients-1],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					// let's not forget once the server sends the diff to the
					// client, the slice of nodes added and removed gets cleaned
					// up
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							ClientID: clientIDs[0],
							Self:     nodeTypes.GetAbsoluteNodeName(),
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a new client, however the randomizer allocated an existing clientID, so we should return a empty clientID",
			setupArgs: func() args {
				return args{
					params: GetClusterNodesParams{
						ClientID: &zero,
					},
					nodeManager: g.nm,
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							Self: nodeTypes.GetAbsoluteNodeName(),
						},
					},
				}
			},
		},
		{
			name: "retrieve nodes for a client that does not want to have diffs, leave all other stored clients alone",
			setupArgs: func() args {
				return args{
					params:      GetClusterNodesParams{},
					nodeManager: g.nm,
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() want {
				return want{
					clients: map[int64]*clusterNodesClient{
						clientIDs[0]: {
							ClusterNodeStatus: &models.ClusterNodeStatus{
								ClientID: clientIDs[0],
								Self:     nodeTypes.GetAbsoluteNodeName(),
								NodesAdded: []*models.NodeElement{
									{
										Name: "random-node-added",
									},
								},
							},
						},
					},
					responder: &GetClusterNodesOK{
						Payload: &models.ClusterNodeStatus{
							Self: nodeTypes.GetAbsoluteNodeName(),
						},
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Log(tt.name)
		randSrc.Seed(0, 0)
		args := tt.setupArgs()
		want := tt.setupWanted()
		h := &getClusterNodesRestApiHandler{
			nodeManager: args.nodeManager,
			clients:     args.clients,
		}
		responder := h.Handle(args.params)
		require.Len(t, h.clients, len(want.clients))
		for k, v := range h.clients {
			wantClient, ok := want.clients[k]
			require.True(t, ok)
			require.Equal(t, wantClient.ClusterNodeStatus, v.ClusterNodeStatus)
		}
		require.Equal(t, middleware.Responder(want.responder), responder)
	}
}

func Test_cleanupClients(t *testing.T) {
	g := setupGetNodesSuite(t)

	now := time.Now()
	type args struct {
		clients map[int64]*clusterNodesClient
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() args
	}{
		{
			name: "delete expired clients",
			setupArgs: func() args {
				return args{
					clients: map[int64]*clusterNodesClient{
						0: {
							lastSync: now.Add(-clientGCTimeout),
						},
						1: {
							lastSync: now,
						},
					},
				}
			},
			setupWanted: func() args {
				return args{
					clients: map[int64]*clusterNodesClient{
						1: {
							lastSync: now,
						},
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		h := &getClusterNodesRestApiHandler{
			nodeManager: g.nm,
			clients:     args.clients,
		}
		h.cleanupClients()
		require.Equal(t, want.clients, h.clients)
	}
}

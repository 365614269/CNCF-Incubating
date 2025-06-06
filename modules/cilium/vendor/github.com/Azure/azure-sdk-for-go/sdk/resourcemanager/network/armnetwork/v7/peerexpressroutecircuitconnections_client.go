// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armnetwork

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// PeerExpressRouteCircuitConnectionsClient contains the methods for the PeerExpressRouteCircuitConnections group.
// Don't use this type directly, use NewPeerExpressRouteCircuitConnectionsClient() instead.
type PeerExpressRouteCircuitConnectionsClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewPeerExpressRouteCircuitConnectionsClient creates a new instance of PeerExpressRouteCircuitConnectionsClient with the specified values.
//   - subscriptionID - The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription
//     ID forms part of the URI for every service call.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewPeerExpressRouteCircuitConnectionsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*PeerExpressRouteCircuitConnectionsClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &PeerExpressRouteCircuitConnectionsClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// Get - Gets the specified Peer Express Route Circuit Connection from the specified express route circuit.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - circuitName - The name of the express route circuit.
//   - peeringName - The name of the peering.
//   - connectionName - The name of the peer express route circuit connection.
//   - options - PeerExpressRouteCircuitConnectionsClientGetOptions contains the optional parameters for the PeerExpressRouteCircuitConnectionsClient.Get
//     method.
func (client *PeerExpressRouteCircuitConnectionsClient) Get(ctx context.Context, resourceGroupName string, circuitName string, peeringName string, connectionName string, options *PeerExpressRouteCircuitConnectionsClientGetOptions) (PeerExpressRouteCircuitConnectionsClientGetResponse, error) {
	var err error
	const operationName = "PeerExpressRouteCircuitConnectionsClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, resourceGroupName, circuitName, peeringName, connectionName, options)
	if err != nil {
		return PeerExpressRouteCircuitConnectionsClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return PeerExpressRouteCircuitConnectionsClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return PeerExpressRouteCircuitConnectionsClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *PeerExpressRouteCircuitConnectionsClient) getCreateRequest(ctx context.Context, resourceGroupName string, circuitName string, peeringName string, connectionName string, _ *PeerExpressRouteCircuitConnectionsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/expressRouteCircuits/{circuitName}/peerings/{peeringName}/peerConnections/{connectionName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if circuitName == "" {
		return nil, errors.New("parameter circuitName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{circuitName}", url.PathEscape(circuitName))
	if peeringName == "" {
		return nil, errors.New("parameter peeringName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{peeringName}", url.PathEscape(peeringName))
	if connectionName == "" {
		return nil, errors.New("parameter connectionName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{connectionName}", url.PathEscape(connectionName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *PeerExpressRouteCircuitConnectionsClient) getHandleResponse(resp *http.Response) (PeerExpressRouteCircuitConnectionsClientGetResponse, error) {
	result := PeerExpressRouteCircuitConnectionsClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.PeerExpressRouteCircuitConnection); err != nil {
		return PeerExpressRouteCircuitConnectionsClientGetResponse{}, err
	}
	return result, nil
}

// NewListPager - Gets all global reach peer connections associated with a private peering in an express route circuit.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - circuitName - The name of the circuit.
//   - peeringName - The name of the peering.
//   - options - PeerExpressRouteCircuitConnectionsClientListOptions contains the optional parameters for the PeerExpressRouteCircuitConnectionsClient.NewListPager
//     method.
func (client *PeerExpressRouteCircuitConnectionsClient) NewListPager(resourceGroupName string, circuitName string, peeringName string, options *PeerExpressRouteCircuitConnectionsClientListOptions) *runtime.Pager[PeerExpressRouteCircuitConnectionsClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[PeerExpressRouteCircuitConnectionsClientListResponse]{
		More: func(page PeerExpressRouteCircuitConnectionsClientListResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *PeerExpressRouteCircuitConnectionsClientListResponse) (PeerExpressRouteCircuitConnectionsClientListResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "PeerExpressRouteCircuitConnectionsClient.NewListPager")
			nextLink := ""
			if page != nil {
				nextLink = *page.NextLink
			}
			resp, err := runtime.FetcherForNextLink(ctx, client.internal.Pipeline(), nextLink, func(ctx context.Context) (*policy.Request, error) {
				return client.listCreateRequest(ctx, resourceGroupName, circuitName, peeringName, options)
			}, nil)
			if err != nil {
				return PeerExpressRouteCircuitConnectionsClientListResponse{}, err
			}
			return client.listHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listCreateRequest creates the List request.
func (client *PeerExpressRouteCircuitConnectionsClient) listCreateRequest(ctx context.Context, resourceGroupName string, circuitName string, peeringName string, _ *PeerExpressRouteCircuitConnectionsClientListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/expressRouteCircuits/{circuitName}/peerings/{peeringName}/peerConnections"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if circuitName == "" {
		return nil, errors.New("parameter circuitName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{circuitName}", url.PathEscape(circuitName))
	if peeringName == "" {
		return nil, errors.New("parameter peeringName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{peeringName}", url.PathEscape(peeringName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// listHandleResponse handles the List response.
func (client *PeerExpressRouteCircuitConnectionsClient) listHandleResponse(resp *http.Response) (PeerExpressRouteCircuitConnectionsClientListResponse, error) {
	result := PeerExpressRouteCircuitConnectionsClientListResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.PeerExpressRouteCircuitConnectionListResult); err != nil {
		return PeerExpressRouteCircuitConnectionsClientListResponse{}, err
	}
	return result, nil
}

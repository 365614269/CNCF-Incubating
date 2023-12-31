// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package bgp

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetBgpRoutePoliciesHandlerFunc turns a function with the right signature into a get bgp route policies handler
type GetBgpRoutePoliciesHandlerFunc func(GetBgpRoutePoliciesParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetBgpRoutePoliciesHandlerFunc) Handle(params GetBgpRoutePoliciesParams) middleware.Responder {
	return fn(params)
}

// GetBgpRoutePoliciesHandler interface for that can handle valid get bgp route policies params
type GetBgpRoutePoliciesHandler interface {
	Handle(GetBgpRoutePoliciesParams) middleware.Responder
}

// NewGetBgpRoutePolicies creates a new http.Handler for the get bgp route policies operation
func NewGetBgpRoutePolicies(ctx *middleware.Context, handler GetBgpRoutePoliciesHandler) *GetBgpRoutePolicies {
	return &GetBgpRoutePolicies{Context: ctx, Handler: handler}
}

/*
	GetBgpRoutePolicies swagger:route GET /bgp/route-policies bgp getBgpRoutePolicies

Lists BGP route policies configured in BGP Control Plane.

Retrieves route policies from BGP Control Plane.
*/
type GetBgpRoutePolicies struct {
	Context *middleware.Context
	Handler GetBgpRoutePoliciesHandler
}

func (o *GetBgpRoutePolicies) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewGetBgpRoutePoliciesParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}

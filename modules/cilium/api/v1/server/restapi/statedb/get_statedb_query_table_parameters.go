// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package statedb

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// NewGetStatedbQueryTableParams creates a new GetStatedbQueryTableParams object
//
// There are no default values defined in the spec.
func NewGetStatedbQueryTableParams() GetStatedbQueryTableParams {

	return GetStatedbQueryTableParams{}
}

// GetStatedbQueryTableParams contains all the bound params for the get statedb query table operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetStatedbQueryTable
type GetStatedbQueryTableParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*StateDB index name
	  Required: true
	  In: query
	*/
	Index string
	/*Query key (base64 encoded)
	  Required: true
	  In: query
	*/
	Key string
	/*If true perform a LowerBound search
	  Required: true
	  In: query
	*/
	Lowerbound bool
	/*StateDB table name
	  Required: true
	  In: path
	*/
	Table string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetStatedbQueryTableParams() beforehand.
func (o *GetStatedbQueryTableParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qIndex, qhkIndex, _ := qs.GetOK("index")
	if err := o.bindIndex(qIndex, qhkIndex, route.Formats); err != nil {
		res = append(res, err)
	}

	qKey, qhkKey, _ := qs.GetOK("key")
	if err := o.bindKey(qKey, qhkKey, route.Formats); err != nil {
		res = append(res, err)
	}

	qLowerbound, qhkLowerbound, _ := qs.GetOK("lowerbound")
	if err := o.bindLowerbound(qLowerbound, qhkLowerbound, route.Formats); err != nil {
		res = append(res, err)
	}

	rTable, rhkTable, _ := route.Params.GetOK("table")
	if err := o.bindTable(rTable, rhkTable, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindIndex binds and validates parameter Index from query.
func (o *GetStatedbQueryTableParams) bindIndex(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("index", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false

	if err := validate.RequiredString("index", "query", raw); err != nil {
		return err
	}
	o.Index = raw

	return nil
}

// bindKey binds and validates parameter Key from query.
func (o *GetStatedbQueryTableParams) bindKey(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("key", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false

	if err := validate.RequiredString("key", "query", raw); err != nil {
		return err
	}
	o.Key = raw

	return nil
}

// bindLowerbound binds and validates parameter Lowerbound from query.
func (o *GetStatedbQueryTableParams) bindLowerbound(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("lowerbound", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false

	if err := validate.RequiredString("lowerbound", "query", raw); err != nil {
		return err
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("lowerbound", "query", "bool", raw)
	}
	o.Lowerbound = value

	return nil
}

// bindTable binds and validates parameter Table from path.
func (o *GetStatedbQueryTableParams) bindTable(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route
	o.Table = raw

	return nil
}

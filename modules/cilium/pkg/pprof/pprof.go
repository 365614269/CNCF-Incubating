// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package pprof enables use of pprof in Cilium
package pprof

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Enable runs an HTTP server to serve the pprof API
//
// Deprecated: use pprof.Cell() instead.
func Enable(logger *slog.Logger, host string, port int) {
	var apiAddress = net.JoinHostPort(host, strconv.Itoa(port))
	go func() {
		if err := http.ListenAndServe(apiAddress, nil); !errors.Is(err, http.ErrServerClosed) {
			logger.Warn("Unable to serve pprof API", logfields.Error, err)
		}
	}()
}

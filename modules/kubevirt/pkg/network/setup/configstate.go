/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2023 Red Hat, Inc.
 *
 */

package network

import (
	"fmt"

	v1 "kubevirt.io/api/core/v1"

	"k8s.io/apimachinery/pkg/util/errors"

	"kubevirt.io/client-go/log"

	"kubevirt.io/kubevirt/pkg/network/cache"
	neterrors "kubevirt.io/kubevirt/pkg/network/errors"
)

type configStateCacheRUD interface {
	Read(networkName string) (cache.PodIfaceState, error)
	Write(networkName string, state cache.PodIfaceState) error
	Delete(networkName string) error
}

type ConfigState struct {
	cache configStateCacheRUD
	ns    NSExecutor
}

func NewConfigState(configStateCache configStateCacheRUD, ns NSExecutor) ConfigState {
	return ConfigState{cache: configStateCache, ns: ns}
}

// Run passes through the state machine flow, executing the following steps:
// - PreRun processes the nics and potentially updates and filters them (e.g. filter-out networks marked for removal).
// - Discover the current pod network configuration status and persist some of it for future use.
// - Configure the pod network.
//
// The discovery step can be executed repeatedly with no limitation.
// The configuration step is allowed to run only once. Any attempt to run it again will cause a critical error.
func (c *ConfigState) Run(nics []podNIC, preRunFunc func([]podNIC) ([]podNIC, error), discoverFunc func(*podNIC) error, configFunc func(*podNIC) error) error {
	var pendingNICs []podNIC
	for _, nic := range nics {
		state, err := c.cache.Read(nic.vmiSpecNetwork.Name)
		if err != nil {
			return err
		}

		switch state {
		case cache.PodIfaceNetworkPreparationPending:
			pendingNICs = append(pendingNICs, nic)
		case cache.PodIfaceNetworkPreparationStarted:
			return neterrors.CreateCriticalNetworkError(
				fmt.Errorf("network %s preparation cannot be restarted", nic.vmiSpecNetwork.Name),
			)
		}
	}
	nics = pendingNICs

	if len(pendingNICs) == 0 {
		return nil
	}

	err := c.ns.Do(func() error {
		var preErr error
		nics, preErr = preRunFunc(nics)
		if preErr != nil {
			return preErr
		}
		return c.plug(nics, discoverFunc, configFunc)
	})
	return err
}

func (c *ConfigState) plug(nics []podNIC, discoverFunc func(*podNIC) error, configFunc func(*podNIC) error) error {
	for i := range nics {
		if ferr := discoverFunc(&nics[i]); ferr != nil {
			return ferr
		}
	}

	for _, nic := range nics {
		if werr := c.cache.Write(nic.vmiSpecNetwork.Name, cache.PodIfaceNetworkPreparationStarted); werr != nil {
			return fmt.Errorf("failed to mark configuration as started for %s: %w", nic.vmiSpecNetwork.Name, werr)
		}
	}

	// The discovery step must be called *before* the configuration step, allowing it to persist/cache the
	// original pod network status. The configuration step mutates the pod network.
	for i := range nics {
		if ferr := configFunc(&nics[i]); ferr != nil {
			log.Log.Reason(ferr).Errorf("failed to configure pod network: %s", nics[i].vmiSpecNetwork.Name)
			return neterrors.CreateCriticalNetworkError(ferr)
		}
	}

	for _, nic := range nics {
		if werr := c.cache.Write(nic.vmiSpecNetwork.Name, cache.PodIfaceNetworkPreparationFinished); werr != nil {
			return neterrors.CreateCriticalNetworkError(
				fmt.Errorf("failed to mark configuration as finished for %s: %w", nic.vmiSpecNetwork.Name, werr),
			)
		}
	}
	return nil
}

func (c *ConfigState) Unplug(networks []v1.Network, filterFunc func([]v1.Network) ([]string, error), cleanupFunc func(string) error) error {
	var nonPendingNetworks []v1.Network
	var err error
	if nonPendingNetworks, err = c.nonPendingNetworks(networks); err != nil {
		return err
	}

	if len(nonPendingNetworks) == 0 {
		return nil
	}
	err = c.ns.Do(func() error {
		networksToUnplug, doErr := filterFunc(nonPendingNetworks)
		if doErr != nil {
			return doErr
		}

		var cleanupErrors []error
		for _, net := range networksToUnplug {
			if cleanupErr := cleanupFunc(net); cleanupErr != nil {
				cleanupErrors = append(cleanupErrors, cleanupErr)
			} else if cleanupErr := c.cache.Delete(net); cleanupErr != nil {
				cleanupErrors = append(cleanupErrors, cleanupErr)
			}
		}
		return errors.NewAggregate(cleanupErrors)
	})
	return err
}

func (c *ConfigState) nonPendingNetworks(networks []v1.Network) ([]v1.Network, error) {
	var nonPendingNetworks []v1.Network

	for _, net := range networks {

		state, err := c.cache.Read(net.Name)
		if err != nil {
			return nil, err
		}
		if state != cache.PodIfaceNetworkPreparationPending {
			nonPendingNetworks = append(nonPendingNetworks, net)
		}
	}
	return nonPendingNetworks, nil
}

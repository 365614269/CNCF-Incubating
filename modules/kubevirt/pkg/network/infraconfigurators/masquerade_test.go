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
 * Copyright 2021 Red Hat, Inc.
 *
 */

package infraconfigurators

import (
	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"kubevirt.io/client-go/api"

	"github.com/vishvananda/netlink"

	v1 "kubevirt.io/api/core/v1"

	netdriver "kubevirt.io/kubevirt/pkg/network/driver"
)

var _ = Describe("Masquerade infrastructure configurator", func() {
	var (
		ctrl    *gomock.Controller
		handler *netdriver.MockNetworkHandler
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		handler = netdriver.NewMockNetworkHandler(ctrl)
	})

	const (
		bridgeIfaceName = "k6t-eth0"
	)

	newVMIMasqueradeInterface := func(namespace string, name string, ports ...int) *v1.VirtualMachineInstance {
		vmi := api.NewMinimalVMIWithNS(namespace, name)
		vmi.Spec.Networks = []v1.Network{*v1.DefaultPodNetwork()}
		var portList []v1.Port
		for i, port := range ports {
			portList = append(portList, v1.Port{
				Name:     fmt.Sprintf("port%d", i),
				Protocol: "tcp",
				Port:     int32(port),
			})
		}
		vmi.Spec.Domain.Devices.Interfaces = []v1.Interface{
			{
				Name: "default",
				InterfaceBindingMethod: v1.InterfaceBindingMethod{
					Masquerade: &v1.InterfaceMasquerade{},
				},
				Ports: portList,
			},
		}
		v1.SetObjectDefaults_VirtualMachineInstance(vmi)
		return vmi
	}

	Context("discover link information", func() {
		const (
			expectedVMInternalIPStr   = "10.0.2.2/24"
			expectedVMGatewayIPStr    = "10.0.2.1/24"
			expectedVMInternalIPv6Str = "fd10:0:2::2/120"
			expectedVMGatewayIPv6Str  = "fd10:0:2::1/120"
			ifaceName                 = "eth0"
			bridgeIfaceName           = "k6t-eth0"
			launcherPID               = 1000
		)

		var (
			masqueradeConfigurator *MasqueradePodNetworkConfigurator
			podLink                *netlink.GenericLink
			vmi                    *v1.VirtualMachineInstance
		)

		BeforeEach(func() {
			vmi = newVMIMasqueradeInterface("default", "vm1")
			masqueradeConfigurator = NewMasqueradePodNetworkConfigurator(vmi, &vmi.Spec.Domain.Devices.Interfaces[0], &vmi.Spec.Networks[0], launcherPID, handler)
		})

		When("the pod link is defined", func() {
			BeforeEach(func() {
				podLink = &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: ifaceName, MTU: 1000}}
				handler.EXPECT().LinkByName(ifaceName).Return(podLink, nil)
			})

			It("succeeds reading the pod link, and generate bridge iface name", func() {
				handler.EXPECT().HasIPv4GlobalUnicastAddress(gomock.Any())
				handler.EXPECT().HasIPv6GlobalUnicastAddress(gomock.Any())

				Expect(masqueradeConfigurator.DiscoverPodNetworkInterface(ifaceName)).To(Succeed())
				Expect(masqueradeConfigurator.podNicLink).To(Equal(podLink))
				Expect(masqueradeConfigurator.bridgeInterfaceName).To(Equal(bridgeIfaceName))
			})

			When("the pod interface has an IPv4 address", func() {
				When("and is missing an IPv6 address", func() {
					BeforeEach(func() {
						handler.EXPECT().HasIPv4GlobalUnicastAddress(ifaceName).Return(true, nil)
						handler.EXPECT().HasIPv6GlobalUnicastAddress(ifaceName).Return(false, nil)
					})

					It("should succeed discovering the pod link info", func() {
						Expect(masqueradeConfigurator.DiscoverPodNetworkInterface(ifaceName)).To(Succeed())
						Expect(masqueradeConfigurator.podNicLink).To(Equal(podLink))
						expectedGwIP, _ := netlink.ParseAddr(expectedVMGatewayIPStr)
						Expect(masqueradeConfigurator.vmGatewayAddr).To(Equal(expectedGwIP))
						expectedVMIP, _ := netlink.ParseAddr(expectedVMInternalIPStr)
						Expect(masqueradeConfigurator.vmIPv4Addr).To(Equal(*expectedVMIP))
						Expect(masqueradeConfigurator.vmGatewayIpv6Addr).To(BeNil())
					})
				})

				When("and we fail to understand if there's an IPv6 configuration", func() {
					BeforeEach(func() {
						handler.EXPECT().HasIPv4GlobalUnicastAddress(ifaceName).Return(true, nil)
						handler.EXPECT().HasIPv6GlobalUnicastAddress(ifaceName).Return(true, fmt.Errorf("failed to check pod's IPv6 configuration"))
					})

					It("should fail to discover the pod's link information", func() {
						Expect(masqueradeConfigurator.DiscoverPodNetworkInterface(ifaceName)).To(HaveOccurred())
					})
				})
			})

			When("the pod interface has both IPv4 and IPv6 addresses", func() {
				BeforeEach(func() {
					handler.EXPECT().HasIPv4GlobalUnicastAddress(ifaceName).Return(true, nil)
					handler.EXPECT().HasIPv6GlobalUnicastAddress(ifaceName).Return(true, nil)
				})

				It("should succeed reading the pod link info", func() {
					Expect(masqueradeConfigurator.DiscoverPodNetworkInterface(ifaceName)).To(Succeed())
					Expect(masqueradeConfigurator.podNicLink).To(Equal(podLink))
					expectedGwIP, _ := netlink.ParseAddr(expectedVMGatewayIPStr)
					Expect(masqueradeConfigurator.vmGatewayAddr).To(Equal(expectedGwIP))
					expectedVMIP, _ := netlink.ParseAddr(expectedVMInternalIPStr)
					Expect(masqueradeConfigurator.vmIPv4Addr).To(Equal(*expectedVMIP))
					expectedGwIPv6, _ := netlink.ParseAddr(expectedVMGatewayIPv6Str)
					Expect(masqueradeConfigurator.vmGatewayIpv6Addr).To(Equal(expectedGwIPv6))
					expectedVMIPv6, _ := netlink.ParseAddr(expectedVMInternalIPv6Str)
					Expect(masqueradeConfigurator.vmIPv6Addr).To(Equal(*expectedVMIPv6))
				})
			})

			When("the pod interface has an IPv6 address", func() {
				When("and is missing an IPv4 address", func() {
					BeforeEach(func() {
						handler.EXPECT().HasIPv4GlobalUnicastAddress(ifaceName).Return(false, nil)
						handler.EXPECT().HasIPv6GlobalUnicastAddress(ifaceName).Return(true, nil)
					})

					It("should succeed discovering the pod link info", func() {
						Expect(masqueradeConfigurator.DiscoverPodNetworkInterface(ifaceName)).To(Succeed())
						Expect(masqueradeConfigurator.podNicLink).To(Equal(podLink))
						expectedGwIPv6, _ := netlink.ParseAddr(expectedVMGatewayIPv6Str)
						Expect(masqueradeConfigurator.vmGatewayIpv6Addr).To(Equal(expectedGwIPv6))
						expectedVMIPv6, _ := netlink.ParseAddr(expectedVMInternalIPv6Str)
						Expect(masqueradeConfigurator.vmIPv6Addr).To(Equal(*expectedVMIPv6))
						Expect(masqueradeConfigurator.vmGatewayAddr).To(BeNil())
					})
				})
			})
		})

		When("the pod link information cannot be retrieved", func() {
			BeforeEach(func() {
				handler.EXPECT().LinkByName(ifaceName).Return(nil, fmt.Errorf("cannot get pod link"))
			})

			It("should fail to discover the pod's link information", func() {
				Expect(masqueradeConfigurator.DiscoverPodNetworkInterface(ifaceName)).To(HaveOccurred())
			})
		})
	})
})

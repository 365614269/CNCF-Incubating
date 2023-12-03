/*
 * This file is part of the kubevirt project
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
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/tests"
	"kubevirt.io/kubevirt/tests/console"
	"kubevirt.io/kubevirt/tests/decorators"
	"kubevirt.io/kubevirt/tests/framework/kubevirt"
	"kubevirt.io/kubevirt/tests/libkvconfig"
	"kubevirt.io/kubevirt/tests/libvmi"
	"kubevirt.io/kubevirt/tests/libwait"
	"kubevirt.io/kubevirt/tests/testsuite"

	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
)

const (
	passtBindingName  = "passt"
	passtSidecarImage = "registry:5000/kubevirt/network-passt-binding:devel"
	passtNetAttDef    = "netbindingpasst"
	passtType         = "kubevirt-passt-binding"
)

var _ = SIGDescribe("[Serial]network binding plugin", Serial, decorators.NetCustomBindingPlugins, func() {

	BeforeEach(func() {
		tests.EnableFeatureGate(virtconfig.NetworkBindingPlugingsGate)
	})

	Context("passt", func() {
		BeforeEach(func() {
			err := libkvconfig.WithNetBindingPlugin(passtBindingName, v1.InterfaceBindingPlugin{
				SidecarImage:                passtSidecarImage,
				NetworkAttachmentDefinition: passtNetAttDef,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		BeforeEach(func() {
			namespace := testsuite.GetTestNamespace(nil)
			Expect(createBasicNetworkAttachmentDefinition(namespace, passtNetAttDef, passtType)).To(Succeed())
		})

		It("can be used by a VM as its primary network", func() {
			const (
				macAddress = "02:00:00:00:00:02"
			)
			passtIface := libvmi.InterfaceDeviceWithBindingPlugin(
				libvmi.DefaultInterfaceName, v1.PluginBinding{Name: passtBindingName},
			)
			passtIface.MacAddress = macAddress
			vmi := libvmi.NewAlpineWithTestTooling(
				libvmi.WithInterface(passtIface),
				libvmi.WithNetwork(v1.DefaultPodNetwork()),
			)
			vm := tests.NewRandomVirtualMachine(vmi, true)

			var err error
			namespace := testsuite.GetTestNamespace(nil)
			vm, err = kubevirt.Client().VirtualMachine(namespace).Create(context.Background(), vm)
			Expect(err).ToNot(HaveOccurred())

			vmi.Namespace = vm.Namespace
			vmi = libwait.WaitUntilVMIReady(
				vmi,
				console.LoginToAlpine,
				libwait.WithFailOnWarnings(false),
				libwait.WithTimeout(180),
			)

			Expect(vmi.Status.Interfaces).To(HaveLen(1))
			Expect(vmi.Status.Interfaces[0].IPs).NotTo(BeEmpty())
			Expect(vmi.Status.Interfaces[0].IP).NotTo(BeEmpty())
			Expect(vmi.Status.Interfaces[0].MAC).To(Equal(macAddress))
		})
	})

	Context("macvtap", func() {
		const (
			macvtapNetworkConfNAD = `{"apiVersion":"k8s.cni.cncf.io/v1","kind":"NetworkAttachmentDefinition","metadata":{"name":"%s","namespace":"%s", "annotations": {"k8s.v1.cni.cncf.io/resourceName": "macvtap.network.kubevirt.io/%s"}},"spec":{"config":"{ \"cniVersion\": \"0.3.1\", \"name\": \"%s\", \"type\": \"macvtap\"}"}}`
			macvtapBindingName    = "macvtap"
			macvtapLowerDevice    = "eth0"
			macvtapNetworkName    = "net1"
		)

		BeforeEach(func() {
			macvtapNad := fmt.Sprintf(macvtapNetworkConfNAD, macvtapNetworkName, testsuite.GetTestNamespace(nil), macvtapLowerDevice, macvtapNetworkName)
			namespace := testsuite.GetTestNamespace(nil)
			Expect(createNetworkAttachmentDefinition(kubevirt.Client(), macvtapNetworkName, namespace, macvtapNad)).
				To(Succeed(), "A macvtap network named %s should be provisioned", macvtapNetworkName)
		})

		BeforeEach(func() {
			err := libkvconfig.WithNetBindingPlugin(macvtapBindingName, v1.InterfaceBindingPlugin{DomainAttachmentType: v1.Tap})
			Expect(err).NotTo(HaveOccurred())
		})

		It("can run a virtual machine with one macvtap interface", func() {
			var vmi *v1.VirtualMachineInstance
			var chosenMAC string

			chosenMACHW, err := GenerateRandomMac()
			Expect(err).ToNot(HaveOccurred())
			chosenMAC = chosenMACHW.String()

			ifaceName := "macvtapIface"
			macvtapIface := libvmi.InterfaceDeviceWithBindingPlugin(
				ifaceName, v1.PluginBinding{Name: macvtapBindingName},
			)
			vmi = libvmi.NewAlpineWithTestTooling(
				libvmi.WithInterface(
					*libvmi.InterfaceWithMac(&macvtapIface, chosenMAC)),
				libvmi.WithNetwork(libvmi.MultusNetwork(ifaceName, macvtapNetworkName)))

			vmi, err = kubevirt.Client().VirtualMachineInstance(testsuite.GetTestNamespace(nil)).Create(context.Background(), vmi)
			Expect(err).NotTo(HaveOccurred())
			vmi = libwait.WaitUntilVMIReady(
				vmi,
				console.LoginToAlpine)

			Expect(vmi.Status.Interfaces).To(HaveLen(1), "should have a single interface")
			Expect(vmi.Status.Interfaces[0].MAC).To(Equal(chosenMAC), "the expected MAC address should be set in the VMI")
		})

	})
})

func createBasicNetworkAttachmentDefinition(namespace, nadName, typeName string) error {
	const netAttDefBasicFormat = `{"apiVersion":"k8s.cni.cncf.io/v1","kind":"NetworkAttachmentDefinition","metadata":{"name":%q,"namespace":%q},"spec":{"config":"{ \"cniVersion\": \"0.3.1\", \"name\": \"%s\", \"plugins\": [{\"type\": \"%s\"}]}"}}`
	return createNetworkAttachmentDefinition(
		kubevirt.Client(),
		nadName,
		namespace,
		fmt.Sprintf(netAttDefBasicFormat, nadName, namespace, nadName, typeName),
	)
}

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

package admitter_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfield "k8s.io/apimachinery/pkg/util/validation/field"

	"kubevirt.io/client-go/api"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/network/admitter"
)

var _ = Describe("Validating VMI network spec", func() {

	DescribeTable("network interface state valid value", func(value v1.InterfaceState) {
		vm := api.NewMinimalVMI("testvm")
		vm.Spec.Domain.Devices.Interfaces = []v1.Interface{{
			Name:                   "foo",
			State:                  value,
			InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}}},
		}
		Expect(admitter.ValidateInterfaceStateValue(k8sfield.NewPath("fake"), &vm.Spec)).To(BeEmpty())
	},
		Entry("is empty", v1.InterfaceState("")),
		Entry("is absent when bridge binding is used", v1.InterfaceStateAbsent),
	)

	It("network interface state value is invalid", func() {
		vm := api.NewMinimalVMI("testvm")
		vm.Spec.Domain.Devices.Interfaces = []v1.Interface{{Name: "foo", State: v1.InterfaceState("foo")}}
		Expect(admitter.ValidateInterfaceStateValue(k8sfield.NewPath("fake"), &vm.Spec)).To(
			ConsistOf(metav1.StatusCause{
				Type:    "FieldValueInvalid",
				Message: "logical foo interface state value is unsupported: foo",
				Field:   "fake.domain.devices.interfaces[0].state",
			}))
	})

	It("network interface state value of absent is not supported when bridge-binding is not used", func() {
		vm := api.NewMinimalVMI("testvm")
		vm.Spec.Domain.Devices.Interfaces = []v1.Interface{{
			Name:                   "foo",
			State:                  v1.InterfaceStateAbsent,
			InterfaceBindingMethod: v1.InterfaceBindingMethod{Masquerade: &v1.InterfaceMasquerade{}},
		}}
		Expect(admitter.ValidateInterfaceStateValue(k8sfield.NewPath("fake"), &vm.Spec)).To(
			ConsistOf(metav1.StatusCause{
				Type:    "FieldValueInvalid",
				Message: "\"foo\" interface's state \"absent\" is supported only for bridge binding",
				Field:   "fake.domain.devices.interfaces[0].state",
			}))
	})

	It("network interface state value of absent is not supported on the default network", func() {
		vm := api.NewMinimalVMI("testvm")
		vm.Spec.Domain.Devices.Interfaces = []v1.Interface{{
			Name:                   "foo",
			State:                  v1.InterfaceStateAbsent,
			InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}},
		}}
		vm.Spec.Networks = []v1.Network{{Name: "foo", NetworkSource: v1.NetworkSource{Pod: &v1.PodNetwork{}}}}
		Expect(admitter.ValidateInterfaceStateValue(k8sfield.NewPath("fake"), &vm.Spec)).To(
			ConsistOf(metav1.StatusCause{
				Type:    "FieldValueInvalid",
				Message: "\"foo\" interface's state \"absent\" is not supported on default networks",
				Field:   "fake.domain.devices.interfaces[0].state",
			}))
	})

	It("network interface has both binding plugin and interface binding method", func() {
		vm := api.NewMinimalVMI("testvm")
		vm.Spec.Domain.Devices.Interfaces = []v1.Interface{{
			Name:                   "foo",
			InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}},
			Binding:                &v1.PluginBinding{Name: "boo"},
		}}
		Expect(admitter.ValidateInterfaceBinding(k8sfield.NewPath("fake"), &vm.Spec)).To(
			ConsistOf(metav1.StatusCause{
				Type:    "FieldValueInvalid",
				Message: "logical foo interface cannot have both binding plugin and interface binding method",
				Field:   "fake.domain.devices.interfaces[0].binding",
			}))
	})

	It("network interface has only plugin binding", func() {
		vm := api.NewMinimalVMI("testvm")
		vm.Spec.Domain.Devices.Interfaces = []v1.Interface{{
			Name:    "foo",
			Binding: &v1.PluginBinding{Name: "boo"},
		}}
		Expect(admitter.ValidateInterfaceBinding(k8sfield.NewPath("fake"), &vm.Spec)).To(BeEmpty())
	})

	It("network interface has only binding method", func() {
		vm := api.NewMinimalVMI("testvm")
		vm.Spec.Domain.Devices.Interfaces = []v1.Interface{{
			Name:                   "foo",
			InterfaceBindingMethod: v1.InterfaceBindingMethod{Bridge: &v1.InterfaceBridge{}},
		}}
		Expect(admitter.ValidateInterfaceBinding(k8sfield.NewPath("fake"), &vm.Spec)).To(BeEmpty())
	})

	It("support only a single pod network", func() {
		const net1Name = "default"
		const net2Name = "default2"
		vmi := v1.VirtualMachineInstance{}
		vmi.Spec.Networks = []v1.Network{
			{Name: net1Name, NetworkSource: v1.NetworkSource{Pod: &v1.PodNetwork{}}},
			{Name: net2Name, NetworkSource: v1.NetworkSource{Pod: &v1.PodNetwork{}}},
		}
		causes := admitter.ValidateSinglePodNetwork(k8sfield.NewPath("fake"), &vmi.Spec)
		Expect(causes).To(HaveLen(1))
		Expect(causes[0].Message).To(Equal("more than one interface is connected to a pod network in fake.interfaces"))
	})
})

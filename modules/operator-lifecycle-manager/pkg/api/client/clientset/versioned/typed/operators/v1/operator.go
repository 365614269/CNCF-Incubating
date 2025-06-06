/*
Copyright Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	context "context"

	operatorsv1 "github.com/operator-framework/api/pkg/operators/v1"
	scheme "github.com/operator-framework/operator-lifecycle-manager/pkg/api/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// OperatorsGetter has a method to return a OperatorInterface.
// A group's client should implement this interface.
type OperatorsGetter interface {
	Operators() OperatorInterface
}

// OperatorInterface has methods to work with Operator resources.
type OperatorInterface interface {
	Create(ctx context.Context, operator *operatorsv1.Operator, opts metav1.CreateOptions) (*operatorsv1.Operator, error)
	Update(ctx context.Context, operator *operatorsv1.Operator, opts metav1.UpdateOptions) (*operatorsv1.Operator, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, operator *operatorsv1.Operator, opts metav1.UpdateOptions) (*operatorsv1.Operator, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*operatorsv1.Operator, error)
	List(ctx context.Context, opts metav1.ListOptions) (*operatorsv1.OperatorList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *operatorsv1.Operator, err error)
	OperatorExpansion
}

// operators implements OperatorInterface
type operators struct {
	*gentype.ClientWithList[*operatorsv1.Operator, *operatorsv1.OperatorList]
}

// newOperators returns a Operators
func newOperators(c *OperatorsV1Client) *operators {
	return &operators{
		gentype.NewClientWithList[*operatorsv1.Operator, *operatorsv1.OperatorList](
			"operators",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *operatorsv1.Operator { return &operatorsv1.Operator{} },
			func() *operatorsv1.OperatorList { return &operatorsv1.OperatorList{} },
		),
	}
}

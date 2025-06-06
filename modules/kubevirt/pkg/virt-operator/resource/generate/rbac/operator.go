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
 * Copyright The KubeVirt Authors.
 *
 */
package rbac

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	virtv1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/components"
)

const (
	GroupNameSecurity = "security.openshift.io"
	GroupNameRoute    = "route.openshift.io"
	serviceAccountFmt = "%s:%s:%s"
)

// Used for manifest generation only, not by the operator itself
func GetAllOperator(namespace string) []interface{} {
	return []interface{}{
		newOperatorServiceAccount(namespace),
		NewOperatorRole(namespace),
		newOperatorRoleBinding(namespace),
		NewOperatorClusterRole(),
		newOperatorClusterRoleBinding(namespace),
	}
}

func newOperatorServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      components.OperatorServiceAccountName,
			Labels: map[string]string{
				virtv1.AppLabel: "",
			},
		},
	}
}

// public, because it's used in manifest-templator
func NewOperatorClusterRole() *rbacv1.ClusterRole {
	// These are permissions needed by the operator itself.
	// For successfully deploying KubeVirt with the operator, you need to add everything
	// that the KubeVirt components' rules use, see below
	// (you can't create rules with permissions you don't have yourself)
	operatorRole := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: VersionNamev1,
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: components.OperatorServiceAccountName,
			Labels: map[string]string{
				virtv1.AppLabel: "",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"kubevirt.io",
				},
				Resources: []string{
					"kubevirts",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"patch",
					"update",
					"patch",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"serviceaccounts",
					"services",
					"endpoints",
					// pods/exec is required for testing upgrades - that can be removed when we stop
					// supporting upgrades from versions in which virt-api required pods/exec privileges
					"pods/exec",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"create",
					"update",
					"delete",
					"patch",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"configmaps",
				},
				Verbs: []string{
					"patch",
					"delete",
				},
			},
			{
				APIGroups: []string{
					"batch",
				},
				Resources: []string{
					"jobs",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"create",
					"delete",
					"patch",
				},
			},
			{
				APIGroups: []string{
					"apps",
				},
				Resources: []string{
					"controllerrevisions",
				},
				Verbs: []string{
					"watch",
					"list",
					"create",
					"delete",
					"patch",
				},
			},
			{
				APIGroups: []string{
					"apps",
				},
				Resources: []string{
					"deployments",
					"daemonsets",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"create",
					"delete",
					"patch",
				},
			},
			{
				APIGroups: []string{
					VersionName,
				},
				Resources: []string{
					"clusterroles",
					"clusterrolebindings",
					"roles",
					"rolebindings",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"create",
					"delete",
					"patch",
					"update",
				},
			},
			{
				APIGroups: []string{
					"apiextensions.k8s.io",
				},
				Resources: []string{
					"customresourcedefinitions",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"create",
					"delete",
					"patch",
				},
			},
			{
				APIGroups: []string{
					GroupNameSecurity,
				},
				Resources: []string{
					"securitycontextconstraints",
				},
				Verbs: []string{
					"create",
					"get",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{
					GroupNameSecurity,
				},
				Resources: []string{
					"securitycontextconstraints",
				},
				ResourceNames: []string{
					"privileged",
				},
				Verbs: []string{
					"get",
					"patch",
					"update",
				},
			},
			{
				APIGroups: []string{
					GroupNameSecurity,
				},
				Resources: []string{
					"securitycontextconstraints",
				},
				ResourceNames: []string{
					"kubevirt-handler",
					"kubevirt-controller",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"update",
					"delete",
				},
			},
			{
				APIGroups: []string{
					"admissionregistration.k8s.io",
				},
				Resources: []string{
					"validatingwebhookconfigurations",
					"mutatingwebhookconfigurations",
					"validatingadmissionpolicybindings",
					"validatingadmissionpolicies",
				},
				Verbs: []string{
					"get", "list", "watch", "create", "delete", "update", "patch",
				},
			},
			{
				APIGroups: []string{
					"apiregistration.k8s.io",
				},
				Resources: []string{
					"apiservices",
				},
				Verbs: []string{
					"get", "list", "watch", "create", "delete", "update", "patch",
				},
			},
			{
				APIGroups: []string{
					"monitoring.coreos.com",
				},
				Resources: []string{
					"servicemonitors",
					"prometheusrules",
				},
				Verbs: []string{
					"get", "list", "watch", "create", "delete", "update", "patch",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"namespaces",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"patch",
				},
			},
		},
	}

	// now append all rules needed by KubeVirt's components
	operatorRole.Rules = append(operatorRole.Rules, getKubeVirtComponentsClusterRules()...)
	return operatorRole
}

func getKubeVirtComponentsClusterRules() []rbacv1.PolicyRule {
	var rules []rbacv1.PolicyRule

	// namespace doesn't matter, we are only interested in the rules of ClusterRoles
	all := GetAllApiServer("")
	all = append(all, GetAllController("")...)
	all = append(all, GetAllHandler("")...)
	all = append(all, GetAllExportProxy("")...)
	all = append(all, GetAllSynchronizationController("")...)
	all = append(all, GetAllCluster()...)

	for _, resource := range all {
		switch resource.(type) {
		case *rbacv1.ClusterRole:
			role, _ := resource.(*rbacv1.ClusterRole)
			rules = append(rules, role.Rules...)
		}
	}

	// OLM doesn't support role refs
	// so we need special handling for auth delegation for the apiserver,
	// by adding the rules of the system:auth-delegator role manually
	authDelegationRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"authentication.k8s.io",
			},
			Resources: []string{
				"tokenreviews",
			},
			Verbs: []string{
				"create",
			},
		},
		{
			APIGroups: []string{
				"authorization.k8s.io",
			},
			Resources: []string{
				"subjectaccessreviews",
			},
			Verbs: []string{
				"create",
			},
		},
	}
	rules = append(rules, authDelegationRules...)

	return rules
}

func getKubeVirtComponentsRules() []rbacv1.PolicyRule {
	var rules []rbacv1.PolicyRule

	// namespace doesn't matter, we are only interested in the rules
	all := GetAllApiServer("")
	all = append(all, GetAllController("")...)
	all = append(all, GetAllHandler("")...)
	all = append(all, GetAllExportProxy("")...)
	all = append(all, GetAllSynchronizationController("")...)
	all = append(all, GetAllCluster()...)

	for _, resource := range all {
		switch resource.(type) {
		case *rbacv1.Role:
			role, _ := resource.(*rbacv1.Role)
			rules = append(rules, role.Rules...)
		}
	}

	return rules
}

func newOperatorClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: VersionNamev1,
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: components.OperatorServiceAccountName,
			Labels: map[string]string{
				virtv1.AppLabel: "",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: VersionName,
			Kind:     "ClusterRole",
			Name:     components.OperatorServiceAccountName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: namespace,
				Name:      components.OperatorServiceAccountName,
			},
		},
	}
}

func newOperatorRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: VersionNamev1,
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubevirt-operator-rolebinding",
			Namespace: namespace,
			Labels: map[string]string{
				virtv1.AppLabel: "",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: VersionName,
			Kind:     "Role",
			Name:     components.OperatorServiceAccountName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: namespace,
				Name:      components.OperatorServiceAccountName,
			},
		},
	}
}

// NewOperatorRole creates a Role object for kubevirt-operator.
func NewOperatorRole(namespace string) *rbacv1.Role {
	operatorRole := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: VersionNamev1,
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      components.OperatorServiceAccountName,
			Namespace: namespace,
			Labels: map[string]string{
				virtv1.AppLabel: "",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
				},
				ResourceNames: []string{
					components.KubeVirtCASecretName,
					components.KubeVirtExportCASecretName,
					components.VirtHandlerCertSecretName,
					components.VirtHandlerServerCertSecretName,
					components.VirtOperatorCertSecretName,
					components.VirtApiCertSecretName,
					components.VirtControllerCertSecretName,
					components.VirtExportProxyCertSecretName,
					components.VirtSynchronizationControllerCertSecretName,
					components.VirtSynchronizationControllerServerCertSecretName,
				},
				Verbs: []string{
					"create",
					"get",
					"list",
					"watch",
					"patch",
					"delete",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"configmaps",
				},
				Verbs: []string{
					"create",
					"get",
					"list",
					"watch",
					"patch",
					"delete",
				},
			},
			{
				APIGroups: []string{
					GroupNameRoute,
				},
				Resources: []string{
					"routes",
				},
				Verbs: []string{
					"create",
					"get",
					"list",
					"watch",
					"patch",
					"delete",
				},
			},
			{
				APIGroups: []string{
					GroupNameRoute,
				},
				Resources: []string{
					"routes/custom-host",
				},
				Verbs: []string{
					"create",
				},
			},
			{
				APIGroups: []string{
					"coordination.k8s.io",
				},
				Resources: []string{
					"leases",
				},
				Verbs: []string{
					"get", "list", "watch", "delete", "update", "create", "patch",
				},
			},
		},
	}
	operatorRole.Rules = append(operatorRole.Rules, getKubeVirtComponentsRules()...)
	return operatorRole
}

func GetKubevirtComponentsServiceAccounts(namespace string) map[string]bool {
	usermap := make(map[string]bool)

	prefix := "system:serviceaccount"
	usermap[fmt.Sprintf(serviceAccountFmt, prefix, namespace, components.HandlerServiceAccountName)] = true
	usermap[fmt.Sprintf(serviceAccountFmt, prefix, namespace, components.ApiServiceAccountName)] = true
	usermap[fmt.Sprintf(serviceAccountFmt, prefix, namespace, components.ControllerServiceAccountName)] = true
	usermap[fmt.Sprintf(serviceAccountFmt, prefix, namespace, components.OperatorServiceAccountName)] = true

	return usermap
}

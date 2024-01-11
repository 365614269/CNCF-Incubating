package workload_test

import (
	"context"
	"fmt"

	klcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/test/component/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/storage/names"
)

var _ = Describe("Workload", Ordered, func() {
	var (
		name            string
		namespace       string
		version         string
		applicationName string
	)

	BeforeEach(func() { // list var here they will be copied for every spec
		name = names.SimpleNameGenerator.GenerateName("my-workload-")
		applicationName = names.SimpleNameGenerator.GenerateName("my-app-")
		namespace = "default" // namespaces are not deleted in the api so be careful
		// when creating you can use ignoreAlreadyExists(err error)
		version = "1.0.0"
	})
	Describe("Creation of WorkloadVersion from a new Workload", func() {
		var (
			workload        *klcv1beta1.KeptnWorkload
			workloadVersion *klcv1beta1.KeptnWorkloadVersion
		)

		BeforeEach(func() {
			workload = createWorkloadInCluster(name, namespace, version, applicationName)
		})

		Context("with a new Workload CRD", func() {
			It("should create WorkloadVersion", func() {
				By("Check if WorkloadVersion was created")

				workloadVersion = &klcv1beta1.KeptnWorkloadVersion{}
				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      fmt.Sprintf("%s-%s", workload.Name, workload.Spec.Version),
					}, workloadVersion)
					g.Expect(err).To(BeNil())
					g.Expect(workloadVersion.Spec.WorkloadName).To(Equal(workload.Name))
					g.Expect(workloadVersion.Spec.KeptnWorkloadSpec).To(Equal(workload.Spec))

				}, "30s").Should(Succeed())
			})

		})
		AfterEach(func() {
			By("Cleaning Up KeptnWorkload CRD")
			err := k8sClient.Delete(ctx, workload)
			common.LogErrorIfPresent(err)
			By("Cleaning Up KeptnWorkloadVersion CRD")
			err = k8sClient.Delete(ctx, workloadVersion)
			common.LogErrorIfPresent(err)
		})

	})
})

func createWorkloadInCluster(name string, namespace string, version string, applicationName string) *klcv1beta1.KeptnWorkload {
	workload := &klcv1beta1.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: klcv1beta1.KeptnWorkloadSpec{
			AppName:           applicationName,
			Version:           version,
			ResourceReference: klcv1beta1.ResourceReference{UID: types.UID("uid"), Kind: "Pod", Name: "pod1"},
		},
	}
	By("Invoking Reconciling for Create")

	Expect(k8sClient.Create(ctx, workload)).Should(Succeed())
	return workload
}

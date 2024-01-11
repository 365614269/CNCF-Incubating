package task_test

import (
	"context"

	klcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/test/component/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/storage/names"
)

var _ = Describe("Task", Ordered, func() {
	var (
		name               string
		taskDefinitionName string
		namespace          string
	)

	BeforeEach(func() { // list var here they will be copied for every spec
		name = names.SimpleNameGenerator.GenerateName("test-task-reconciler-")
		taskDefinitionName = names.SimpleNameGenerator.GenerateName("my-taskdef-")
		namespace = "default" // namespaces are not deleted in the api so be careful
	})

	Describe("Creation of a Task", func() {
		var (
			taskDefinition *klcv1beta1.KeptnTaskDefinition
			task           *klcv1beta1.KeptnTask
		)
		Context("with an existing TaskDefinition", func() {
			It("should end up in a failed state if the created job fails", func() {
				taskDefinition = makeTaskDefinition(taskDefinitionName, namespace)
				task = makeTask(name, namespace, taskDefinition.Name)

				By("Verifying that a job has been created")

				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      task.Name,
					}, task)
					g.Expect(err).To(BeNil())
					g.Expect(task.Status.JobName).To(Not(BeEmpty()))
				}, "20s").Should(Succeed())

				createdJob := &batchv1.Job{}

				err := k8sClient.Get(context.TODO(), types.NamespacedName{
					Namespace: namespace,
					Name:      task.Status.JobName,
				}, createdJob)

				Expect(err).To(BeNil())

				By("Setting the Job Status to failed")
				createdJob.Status.Conditions = []batchv1.JobCondition{
					{
						Type: batchv1.JobFailed,
					},
				}

				err = k8sClient.Status().Update(context.TODO(), createdJob)
				Expect(err).To(BeNil())

				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      task.Name,
					}, task)
					g.Expect(err).To(BeNil())
					g.Expect(task.Status.Status).To(Equal(apicommon.StateFailed))
				}, "20s").Should(Succeed())
			})
			It("succeed task if taskDefinition for Deno is present in default Keptn namespace", func() {
				By("create default Keptn namespace")

				ns := &v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: KeptnNamespace,
					},
				}
				err := k8sClient.Create(context.TODO(), ns)
				Expect(err).To(BeNil())

				taskDefinition = makeTaskDefinition(taskDefinitionName, KeptnNamespace)
				task = makeTask(name, namespace, taskDefinition.Name)

				By("Verifying that a job has been created")

				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      task.Name,
					}, task)
					g.Expect(err).To(BeNil())
					g.Expect(task.Status.JobName).To(Not(BeEmpty()))
				}, "20s").Should(Succeed())

				createdJob := &batchv1.Job{}

				err = k8sClient.Get(context.TODO(), types.NamespacedName{
					Namespace: namespace,
					Name:      task.Status.JobName,
				}, createdJob)

				Expect(err).To(BeNil())

				By("Setting the Job Status to complete")
				createdJob.Status.Conditions = []batchv1.JobCondition{
					{
						Type: batchv1.JobComplete,
					},
				}

				err = k8sClient.Status().Update(context.TODO(), createdJob)
				Expect(err).To(BeNil())

				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      task.Name,
					}, task)
					g.Expect(err).To(BeNil())
					g.Expect(task.Status.Status).To(Equal(apicommon.StateSucceeded))
				}, "20s").Should(Succeed())
			})
			It("succeed task if taskDefinition for Container is present in default Keptn namespace", func() {
				By("create default Keptn namespace")

				ns := &v1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: KeptnNamespace,
					},
				}
				err := k8sClient.Create(context.TODO(), ns)
				Expect(common.IgnoreAlreadyExists(err)).To(BeNil())

				taskDefinition = makeContainerTaskDefinition(taskDefinitionName, KeptnNamespace)
				task = makeTask(name, namespace, taskDefinition.Name)

				By("Verifying that a job has been created")

				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      task.Name,
					}, task)
					g.Expect(err).To(BeNil())
					g.Expect(task.Status.JobName).To(Not(BeEmpty()))
				}, "20s").Should(Succeed())

				createdJob := &batchv1.Job{}

				err = k8sClient.Get(context.TODO(), types.NamespacedName{
					Namespace: namespace,
					Name:      task.Status.JobName,
				}, createdJob)

				Expect(err).To(BeNil())

				By("Setting the Job Status to complete")
				createdJob.Status.Conditions = []batchv1.JobCondition{
					{
						Type: batchv1.JobComplete,
					},
				}

				err = k8sClient.Status().Update(context.TODO(), createdJob)
				Expect(err).To(BeNil())

				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      task.Name,
					}, task)
					g.Expect(err).To(BeNil())
					g.Expect(task.Status.Status).To(Equal(apicommon.StateSucceeded))
				}, "20s").Should(Succeed())
			})
			It("should propagate labels and annotations to the job and job pod", func() {
				taskDefinition = makeTaskDefinition(taskDefinitionName, namespace)
				task = makeTask(name, namespace, taskDefinition.Name)

				By("Verifying that a job has been created")

				Eventually(func(g Gomega) {
					err := k8sClient.Get(context.TODO(), types.NamespacedName{
						Namespace: namespace,
						Name:      task.Name,
					}, task)
					g.Expect(err).To(BeNil())
					g.Expect(task.Status.JobName).To(Not(BeEmpty()))
				}, "20s").Should(Succeed())

				createdJob := &batchv1.Job{}

				err := k8sClient.Get(context.TODO(), types.NamespacedName{
					Namespace: namespace,
					Name:      task.Status.JobName,
				}, createdJob)

				Expect(err).To(BeNil())

				Expect(createdJob.Annotations).To(Equal(map[string]string{
					"annotation1":                      "annotation2",
					"keptn.sh/task-name":               task.Name,
					"keptn.sh/version":                 "",
					"keptn.sh/workload":                "my-workload",
					"keptn.sh/app":                     "my-app",
					"batch.kubernetes.io/job-tracking": "",
				}))

				Expect(createdJob.Labels).To(Equal(map[string]string{
					"label1": "label2",
				}))

				val, ok := createdJob.Spec.Template.Labels["label1"]
				Expect(ok && val == "label2").To(BeTrue())

				val, ok = createdJob.Spec.Template.Annotations["annotation1"]
				Expect(ok && val == "annotation2").To(BeTrue())
			})
			AfterEach(func() {
				err := k8sClient.Delete(context.TODO(), taskDefinition)
				common.LogErrorIfPresent(err)
				err = k8sClient.Delete(context.TODO(), task)
				common.LogErrorIfPresent(err)
				err = k8sClient.Delete(context.TODO(), &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      taskDefinition.Status.Function.ConfigMap,
						Namespace: taskDefinition.Namespace,
					},
				})
				common.LogErrorIfPresent(err)
			})
		})
	})
})

func makeTask(name string, namespace, taskDefinitionName string) *klcv1beta1.KeptnTask {
	task := &klcv1beta1.KeptnTask{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"label1": "label2",
			},
			Annotations: map[string]string{
				"annotation1": "annotation2",
			},
		},
		Spec: klcv1beta1.KeptnTaskSpec{
			Context: klcv1beta1.TaskContext{
				WorkloadName: "my-workload",
				AppName:      "my-app",
				AppVersion:   "0.1.0",
			},
			TaskDefinition: taskDefinitionName,
		},
	}

	err := k8sClient.Create(ctx, task)
	Expect(err).To(BeNil())

	return task
}

func makeTaskDefinition(taskDefinitionName, namespace string) *klcv1beta1.KeptnTaskDefinition {
	cmName := "my-cm"
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: namespace,
		},
		Data: map[string]string{
			"code": "console.log('hello');",
		},
	}

	err := k8sClient.Create(context.TODO(), cm)
	Expect(err).To(BeNil())

	taskDefinition := &klcv1beta1.KeptnTaskDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      taskDefinitionName,
			Namespace: namespace,
		},
		Spec: klcv1beta1.KeptnTaskDefinitionSpec{
			Function: &klcv1beta1.RuntimeSpec{
				ConfigMapReference: klcv1beta1.ConfigMapReference{
					Name: cmName,
				},
			},
		},
	}

	err = k8sClient.Create(context.TODO(), taskDefinition)
	Expect(err).To(BeNil())

	err = k8sClient.Get(context.TODO(), types.NamespacedName{
		Namespace: namespace,
		Name:      taskDefinitionName,
	}, taskDefinition)

	Expect(err).To(BeNil())

	taskDefinition.Status.Function.ConfigMap = cmName

	err = k8sClient.Status().Update(ctx, taskDefinition)
	Expect(err).To(BeNil())

	return taskDefinition
}

func makeContainerTaskDefinition(taskDefinitionName, namespace string) *klcv1beta1.KeptnTaskDefinition {

	taskDefinition := &klcv1beta1.KeptnTaskDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      taskDefinitionName,
			Namespace: namespace,
		},
		Spec: klcv1beta1.KeptnTaskDefinitionSpec{
			Container: &klcv1beta1.ContainerSpec{
				Container: &v1.Container{
					Name:  "test",
					Image: "busybox:1.36.0",
				},
			},
		},
	}

	err := k8sClient.Create(context.TODO(), taskDefinition)
	Expect(err).To(BeNil())

	err = k8sClient.Get(context.TODO(), types.NamespacedName{
		Namespace: namespace,
		Name:      taskDefinitionName,
	}, taskDefinition)

	Expect(err).To(BeNil())

	return taskDefinition
}

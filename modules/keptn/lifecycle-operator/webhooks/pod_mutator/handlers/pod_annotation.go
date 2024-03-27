package handlers

import (
	"context"
	"log"

	argov1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/go-logr/logr"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type PodAnnotationHandler struct {
	Client client.Client
	Log    logr.Logger
}

func (p *PodAnnotationHandler) IsAnnotated(ctx context.Context, req *admission.Request, pod *corev1.Pod) bool {
	podIsAnnotated := isPodAnnotated(pod)
	if !podIsAnnotated {
		p.Log.Info("Pod is not annotated, check for parent annotations...")
		podIsAnnotated = p.copyAnnotationsIfParentAnnotated(ctx, req, pod)
	}
	return podIsAnnotated
}

func (p *PodAnnotationHandler) copyAnnotationsIfParentAnnotated(ctx context.Context, req *admission.Request, pod *corev1.Pod) bool {
	podOwner := GetOwnerReference(&pod.ObjectMeta)
	if podOwner.UID == "" {
		return false
	}

	switch podOwner.Kind {
	case "ReplicaSet":
		rs := &appsv1.ReplicaSet{}
		if err := p.Client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: podOwner.Name}, rs); err != nil {
			return false
		}

		rsOwner := GetOwnerReference(&rs.ObjectMeta)
		if rsOwner.UID == "" {
			return false
		}

		if rsOwner.Kind == "Rollout" {
			ro := &argov1alpha1.Rollout{}
			objectContainerMetaData := p.fetchParent(ctx, types.NamespacedName{Name: rsOwner.Name, Namespace: req.Namespace}, ro)
			return copyResourceLabelsIfPresent(objectContainerMetaData, pod)
		}
		dp := &appsv1.Deployment{}
		objectContainerMetaData := p.fetchParent(ctx, types.NamespacedName{Name: rsOwner.Name, Namespace: req.Namespace}, dp)
		return copyResourceLabelsIfPresent(objectContainerMetaData, pod)

	case "StatefulSet":
		sts := &appsv1.StatefulSet{}
		objectContainerMetaData := p.fetchParent(ctx, types.NamespacedName{Name: podOwner.Name, Namespace: req.Namespace}, sts)
		return copyResourceLabelsIfPresent(objectContainerMetaData, pod)
	case "DaemonSet":
		ds := &appsv1.DaemonSet{}
		objectContainerMetaData := p.fetchParent(ctx, types.NamespacedName{Name: podOwner.Name, Namespace: req.Namespace}, ds)
		return copyResourceLabelsIfPresent(objectContainerMetaData, pod)
	default:
		return false
	}
}

func (p *PodAnnotationHandler) fetchParent(ctx context.Context, name types.NamespacedName, objectContainer client.Object) *metav1.ObjectMeta {
	if err := p.Client.Get(ctx, name, objectContainer); err != nil {
		p.Log.Info("Could not find pod parent")
		return nil
	}
	return &metav1.ObjectMeta{
		Labels:      objectContainer.GetLabels(),
		Annotations: objectContainer.GetAnnotations(),
	}
}

func copyResourceLabelsIfPresent(sourceResource *metav1.ObjectMeta, targetPod *corev1.Pod) bool {
	if sourceResource == nil {
		return false
	}
	var workloadName, appName, version, preDeploymentChecks, postDeploymentChecks, preEvaluationChecks, postEvaluationChecks string
	var gotWorkloadName, gotVersion bool
	initEmptyAnnotations(&targetPod.ObjectMeta, 7)

	workloadName, gotWorkloadName = GetLabelOrAnnotation(sourceResource, apicommon.WorkloadAnnotation, apicommon.K8sRecommendedWorkloadAnnotations)
	appName, _ = GetLabelOrAnnotation(sourceResource, apicommon.AppAnnotation, apicommon.K8sRecommendedAppAnnotations)
	version, gotVersion = GetLabelOrAnnotation(sourceResource, apicommon.VersionAnnotation, apicommon.K8sRecommendedVersionAnnotations)
	preDeploymentChecks, _ = GetLabelOrAnnotation(sourceResource, apicommon.PreDeploymentTaskAnnotation, "")
	postDeploymentChecks, _ = GetLabelOrAnnotation(sourceResource, apicommon.PostDeploymentTaskAnnotation, "")
	preEvaluationChecks, _ = GetLabelOrAnnotation(sourceResource, apicommon.PreDeploymentEvaluationAnnotation, "")
	postEvaluationChecks, _ = GetLabelOrAnnotation(sourceResource, apicommon.PostDeploymentEvaluationAnnotation, "")
	containerName, _ := GetLabelOrAnnotation(sourceResource, apicommon.ContainerNameAnnotation, "")
	metadata, _ := GetLabelOrAnnotation(sourceResource, apicommon.MetadataAnnotation, "")

	if gotWorkloadName {
		setMapKey(targetPod.Annotations, apicommon.WorkloadAnnotation, workloadName)

		if !gotVersion {
			version, err := calculateVersion(targetPod, containerName)
			if err != nil {
				log.Println(err)
				return false
			}
			setMapKey(targetPod.Annotations, apicommon.VersionAnnotation, version)
		} else {
			setMapKey(targetPod.Annotations, apicommon.VersionAnnotation, version)
		}

		setMapKey(targetPod.Annotations, apicommon.AppAnnotation, appName)
		setMapKey(targetPod.Annotations, apicommon.PreDeploymentTaskAnnotation, preDeploymentChecks)
		setMapKey(targetPod.Annotations, apicommon.PostDeploymentTaskAnnotation, postDeploymentChecks)
		setMapKey(targetPod.Annotations, apicommon.PreDeploymentEvaluationAnnotation, preEvaluationChecks)
		setMapKey(targetPod.Annotations, apicommon.PostDeploymentEvaluationAnnotation, postEvaluationChecks)
		setMapKey(targetPod.Annotations, apicommon.MetadataAnnotation, metadata)

		return true
	}
	return false
}

func isPodAnnotated(pod *corev1.Pod) bool {
	containerName, _ := GetLabelOrAnnotation(&pod.ObjectMeta, apicommon.ContainerNameAnnotation, "")
	_, gotWorkloadAnnotation := GetLabelOrAnnotation(&pod.ObjectMeta, apicommon.WorkloadAnnotation, apicommon.K8sRecommendedWorkloadAnnotations)
	_, gotVersionAnnotation := GetLabelOrAnnotation(&pod.ObjectMeta, apicommon.VersionAnnotation, apicommon.K8sRecommendedVersionAnnotations)

	if gotWorkloadAnnotation {
		if !gotVersionAnnotation {
			initEmptyAnnotations(&pod.ObjectMeta, 1)
			version, err := calculateVersion(pod, containerName)
			if err != nil {
				log.Println(err)
			} else {
				pod.Annotations[apicommon.VersionAnnotation] = version
			}
		}
		return true
	}
	return false
}

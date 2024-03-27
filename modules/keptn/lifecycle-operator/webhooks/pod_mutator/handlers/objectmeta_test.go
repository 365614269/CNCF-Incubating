package handlers

import (
	"reflect"
	"testing"

	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1/common"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetWorkloadName(t *testing.T) {

	type args struct {
		pod *corev1.Pod
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Return concatenated app name and workload name in lower case when annotations are set",
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							apicommon.AppAnnotation:      appname,
							apicommon.WorkloadAnnotation: "SOME-WORKLOAD-NAME",
						},
					},
				},
			},
			want: "some-app-name-some-workload-name",
		},
		{
			name: "Return concatenated app name and workload name in lower case when labels are set",
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							apicommon.AppAnnotation:      appname,
							apicommon.WorkloadAnnotation: "SOME-WORKLOAD-NAME",
						},
					},
				},
			},
			want: "some-app-name-some-workload-name",
		},
		{
			name: "Return concatenated keptn app name and workload name from annotation in lower case when annotations and labels are set",
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							apicommon.AppAnnotation:      "SOME-APP-NAME-ANNOTATION",
							apicommon.WorkloadAnnotation: "SOME-WORKLOAD-NAME-ANNOTATION",
						},
						Labels: map[string]string{
							apicommon.AppAnnotation:      "SOME-APP-NAME-LABEL",
							apicommon.WorkloadAnnotation: "SOME-WORKLOAD-NAME-LABEL",
						},
					},
				},
			},
			want: "some-app-name-annotation-some-workload-name-annotation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if got := getWorkloadName(&tt.args.pod.ObjectMeta, getAppName(&tt.args.pod.ObjectMeta)); got != tt.want {
				t.Errorf("getWorkloadName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetLabelOrAnnotation(t *testing.T) {
	type args struct {
		resource            *metav1.ObjectMeta
		primaryAnnotation   string
		secondaryAnnotation string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 bool
	}{
		{
			name: "Test if primary annotation is returned from annotations",
			args: args{
				resource: &metav1.ObjectMeta{
					Annotations: map[string]string{
						apicommon.AppAnnotation: appname,
					},
				},
				primaryAnnotation:   apicommon.AppAnnotation,
				secondaryAnnotation: apicommon.K8sRecommendedAppAnnotations,
			},
			want:  appname,
			want1: true,
		},
		{
			name: "Test if secondary annotation is returned from annotations",
			args: args{
				resource: &metav1.ObjectMeta{
					Annotations: map[string]string{
						apicommon.K8sRecommendedAppAnnotations: appname,
					},
				},
				primaryAnnotation:   apicommon.AppAnnotation,
				secondaryAnnotation: apicommon.K8sRecommendedAppAnnotations,
			},
			want:  appname,
			want1: true,
		},
		{
			name: "Test if primary annotation is returned from labels",
			args: args{
				resource: &metav1.ObjectMeta{
					Labels: map[string]string{
						apicommon.AppAnnotation: appname,
					},
				},
				primaryAnnotation:   apicommon.AppAnnotation,
				secondaryAnnotation: apicommon.K8sRecommendedAppAnnotations,
			},
			want:  appname,
			want1: true,
		},
		{
			name: "Test if secondary annotation is returned from labels",
			args: args{
				resource: &metav1.ObjectMeta{
					Labels: map[string]string{
						apicommon.K8sRecommendedAppAnnotations: appname,
					},
				},
				primaryAnnotation:   apicommon.AppAnnotation,
				secondaryAnnotation: apicommon.K8sRecommendedAppAnnotations,
			},
			want:  appname,
			want1: true,
		},
		{
			name: "Test that empty string is returned when no annotations or labels are found",
			args: args{
				resource: &metav1.ObjectMeta{
					Annotations: map[string]string{
						"some-other-annotation": appname,
					},
				},
				primaryAnnotation:   apicommon.AppAnnotation,
				secondaryAnnotation: apicommon.K8sRecommendedAppAnnotations,
			},
			want:  "",
			want1: false,
		},
		{
			name: "Test that empty string is returned when primary annotation cannot be found and secondary annotation is empty",
			args: args{
				resource: &metav1.ObjectMeta{
					Annotations: map[string]string{
						"some-other-annotation": appname,
					},
				},
				primaryAnnotation:   apicommon.AppAnnotation,
				secondaryAnnotation: "",
			},
			want:  "",
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := GetLabelOrAnnotation(tt.args.resource, tt.args.primaryAnnotation, tt.args.secondaryAnnotation)
			if got != tt.want {
				t.Errorf("getLabelOrAnnotation() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getLabelOrAnnotation() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestGetImageVersion(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		want    string
		wantErr bool
	}{
		{
			name:    "Return image version when version is present",
			image:   "my-image:1.0.0",
			want:    "1.0.0",
			wantErr: false,
		},
		{
			name:    "Return error when image version is not present",
			image:   "my-image",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Return error when image version is empty",
			image:   "my-image:",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Return error when image version is latest",
			image:   "my-image:latest",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getImageVersion(tt.image)
			if (err != nil) != tt.wantErr {
				t.Errorf("getImageVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getImageVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_calculateVersion(t *testing.T) {
	tests := []struct {
		name          string
		pod           *corev1.Pod
		containerName string
		want          string
		wantErr       bool
	}{
		{
			name: "simple tag",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "ciao:1.0.0"},
					},
				}},
			containerName: "",
			want:          "1.0.0",
			wantErr:       false,
		}, {
			name: "local registry",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "localhost:5000/node-web-app:1.0.0"},
					},
				}},
			containerName: "",
			want:          "1.0.0",
			wantErr:       false,
		},
		{
			name: "single container with annotation mismatch",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:tag1",
						},
					},
				},
			},
			containerName: "not-container-name",
			want:          "",
			wantErr:       true,
		},
		{
			name: "multiple containers",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Image: "ciao",
						},
						{
							Image: "peppe",
							Env: []corev1.EnvVar{{
								Name:  "test",
								Value: "12",
							},
							}},
					},
				}},
			containerName: "",
			want:          "1253120182", //the hash of ciaopeppetest12
			wantErr:       false,
		},
		{
			name: "multiple containers with annotation",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:tag1",
						},
						{
							Name:  "container-name2",
							Image: "image:tag2",
						},
					},
				},
			},
			containerName: "container-name2",
			want:          "tag2",
			wantErr:       false,
		},
		{
			name: "multiple containers with annotation mismatch",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:tag1",
						},
						{
							Name:  "container-name2",
							Image: "image:tag2",
						},
					},
				},
			},
			containerName: "not-container-name",
			want:          "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := calculateVersion(tt.pod, tt.containerName)
			if (err != nil) != tt.wantErr {
				t.Errorf("calculateVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("calculateVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAppName(t *testing.T) {

	tests := []struct {
		name string
		pod  *corev1.Pod
		want string
	}{
		{
			name: "Return keptn app name in lower case when annotation is set",

			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						apicommon.AppAnnotation: appname,
					},
				},
			},

			want: lowerAppName,
		},
		{
			name: "Return keptn app name in lower case when label is set",

			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						apicommon.AppAnnotation: appname,
					},
				},
			},

			want: lowerAppName,
		},
		{
			name: "Return keptn app name from annotation in lower case when annotation and label is set",

			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						apicommon.AppAnnotation: "SOME-APP-NAME-ANNOTATION",
					},
					Labels: map[string]string{
						apicommon.AppAnnotation: "SOME-APP-NAME-LABEL",
					},
				},
			},

			want: "some-app-name-annotation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAppName(&tt.pod.ObjectMeta); got != tt.want {
				t.Errorf("getAppName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOwnerReference(t *testing.T) {

	ownerRef := metav1.OwnerReference{
		UID:  "the-replicaset-uid",
		Kind: "ReplicaSet",
		Name: "some-name",
	}

	type args struct {
		resource metav1.ObjectMeta
	}
	tests := []struct {
		name string
		args args
		want metav1.OwnerReference
	}{
		{
			name: "Test simple return when UID and Kind is set",
			args: args{
				resource: metav1.ObjectMeta{
					UID: "the-pod-uid",
					OwnerReferences: []metav1.OwnerReference{
						ownerRef,
					},
				},
			},
			want: ownerRef,
		},
		{
			name: "Test return is input argument if owner is not found",
			args: args{
				resource: metav1.ObjectMeta{
					UID: "the-pod-uid",
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "SomeNonExistentType",
							UID:  "the-replicaset-uid",
						},
					},
				},
			},
			want: metav1.OwnerReference{
				UID:  "",
				Kind: "",
				Name: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetOwnerReference(&tt.args.resource); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getOwnerReference() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetMapKey(t *testing.T) {
	testCases := []struct {
		testName       string
		inputMap       map[string]string
		key            string
		value          string
		expectedOutput map[string]string
	}{
		{
			testName: "Set key with non-empty value",
			inputMap: map[string]string{"existingKey": "existingValue"},
			key:      "newKey",
			value:    "newValue",
			expectedOutput: map[string]string{
				"existingKey": "existingValue",
				"newKey":      "newValue",
			},
		},
		{
			testName:       "Set key with empty value",
			inputMap:       map[string]string{"existingKey": "existingValue"},
			key:            "newKey",
			value:          "",
			expectedOutput: map[string]string{"existingKey": "existingValue"},
		},
		{
			testName:       "Set key in nil map",
			inputMap:       nil,
			key:            "newKey",
			value:          "",
			expectedOutput: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			setMapKey(tc.inputMap, tc.key, tc.value)

			require.Equal(t, tc.expectedOutput, tc.inputMap)
		})
	}
}

func TestGetValuesForAnnotations(t *testing.T) {
	// Test case 1: No annotations present
	objMeta := &metav1.ObjectMeta{}
	annotationKey := "example"
	result := getValuesForAnnotations(objMeta, annotationKey)
	// Verify that the result is nil since no annotations are present
	require.Nil(t, result)

	// Test case 2: Annotations present with a valid annotation key
	annotations := "value1,value2,value3"
	objMeta = &metav1.ObjectMeta{
		Annotations: map[string]string{
			annotationKey: annotations,
		},
	}

	result = getValuesForAnnotations(objMeta, annotationKey)
	expected := []string{"value1", "value2", "value3"}
	require.Equal(t, expected, result)

	// Test case 3: Annotations present with a different annotation key
	otherAnnotationKey := "other"
	objMeta = &metav1.ObjectMeta{
		Annotations: map[string]string{
			otherAnnotationKey: "value1,value2,value3",
		},
	}

	result = getValuesForAnnotations(objMeta, annotationKey)
	require.Nil(t, result)
}

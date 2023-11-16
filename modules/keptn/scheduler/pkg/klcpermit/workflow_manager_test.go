package klcpermit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func Test_getCRDName(t *testing.T) {
	Obj := metav1.ObjectMeta{}
	t.Log(len(Obj.Annotations))
	t.Log(Obj.Annotations)
	t.Log(make(map[string]string))

	tests := []struct {
		name string
		pod  *corev1.Pod
		want string
	}{
		{
			name: "properly labeld pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						WorkloadAnnotation: "myworkload",
						VersionAnnotation:  "0.0.1",
						AppAnnotation:      "myapp",
					},
				},
			},
			want: "myapp-myworkload-0.0.1",
		},

		{
			name: "properly annotated pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						WorkloadAnnotation: "myworkload",
						VersionAnnotation:  "0.0.1",
						AppAnnotation:      "myapp",
					},

					Labels: map[string]string{
						WorkloadAnnotation: "myotherworkload",
						VersionAnnotation:  "0.0.1",
						AppAnnotation:      "mynotapp",
					}},
			},
			want: "myapp-myworkload-0.0.1",
		},
		{
			name: "annotated and labeled pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						WorkloadAnnotation: "myworkload",
						VersionAnnotation:  "0.0.1",
						AppAnnotation:      "myapp",
					},
				},
			},
			want: "myapp-myworkload-0.0.1",
		},
		{
			name: "annotated and labeled pod without version",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						WorkloadAnnotation: "myworkload",
						AppAnnotation:      "myapp",
					},
				},
			},
			want: "myapp-myworkload-2166136261",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getCRDName(tt.pod); got != tt.want {
				t.Errorf("getCRDName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_CreateResourceName(t *testing.T) {
	tests := []struct {
		Name  string
		Input []string
		Max   int
		Min   int
		Want  string
	}{
		{
			Name: "parts not exceeding max, not min",
			Input: []string{
				"str1",
				"str2",
				"str3",
			},
			Max:  20,
			Min:  5,
			Want: "str1-str2-str3",
		},
		{
			Name: "1 part exceeding max",
			Input: []string{
				"str1111111111111111111111",
				"str2",
				"str3",
			},
			Max:  20,
			Min:  5,
			Want: "str1111111-str2-str3",
		},
		{
			Name: "2 part exceeding max",
			Input: []string{
				"str1",
				"str222222222222222222222222",
				"str3",
			},
			Max:  20,
			Min:  5,
			Want: "str1-str2222222-str3",
		},
		{
			Name: "1 and 2 part exceeding max",
			Input: []string{
				"str111111111111111111111",
				"str22222222",
				"str3",
			},
			Max:  20,
			Min:  5,
			Want: "str11-str222222-str3",
		},
		{
			Name: "1 and 2 part exceeding max, min needs to be reduced",
			Input: []string{
				"str111111111111111111111",
				"str22222222",
				"str3",
			},
			Max:  20,
			Min:  10,
			Want: "str11-str222222-str3",
		},
		{
			Name: "1 and 2 part exceeding max, min needs to be reduced",
			Input: []string{
				"str111111111111111111111",
				"str22222222",
				"str3",
			},
			Max:  20,
			Min:  20,
			Want: "str11-str222222-str3",
		},
		{
			Name: "1 and 2 part exceeding max, min needs to be reduced",
			Input: []string{
				"str111111111111111111111",
				"str22222222",
				"str3",
			},
			Max:  20,
			Min:  100,
			Want: "str111-str22222-str3",
		},
		{
			Name: "part containing an underscore",
			Input: []string{
				"str_1",
				"str2",
				"str3",
			},
			Max:  20,
			Min:  100,
			Want: "str-1-str2-str3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			require.Equal(t, tt.Want, createResourceName(tt.Max, tt.Min, tt.Input...))
		})
	}
}

func Test_getLabelOrAnnotation(t *testing.T) {
	tests := []struct {
		name                string
		pod                 *corev1.Pod
		primaryAnnotation   string
		secondaryAnnotation string
		want                string
		want1               bool
	}{
		{
			name: "Test if primary annotation is returned from annotations",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AppAnnotation: "some-app-name",
					},
				},
			},
			primaryAnnotation:   AppAnnotation,
			secondaryAnnotation: K8sRecommendedAppAnnotations,
			want:                "some-app-name",
			want1:               true,
		},
		{
			name: "Test if secondary annotation is returned from annotations",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						K8sRecommendedAppAnnotations: "some-app-name",
					},
				},
			},
			primaryAnnotation:   AppAnnotation,
			secondaryAnnotation: K8sRecommendedAppAnnotations,
			want:                "some-app-name",
			want1:               true,
		},
		{
			name: "Test if primary annotation is returned from labels",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						AppAnnotation: "some-app-name",
					},
				},
			},
			primaryAnnotation:   AppAnnotation,
			secondaryAnnotation: K8sRecommendedAppAnnotations,
			want:                "some-app-name",
			want1:               true,
		},
		{
			name: "Test if secondary annotation is returned from labels",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						K8sRecommendedAppAnnotations: "some-app-name",
					},
				},
			},
			primaryAnnotation:   AppAnnotation,
			secondaryAnnotation: K8sRecommendedAppAnnotations,
			want:                "some-app-name",
			want1:               true,
		},
		{
			name: "Test that empty string is returned when no annotations or labels are found",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"some-other-annotation": "some-app-name",
					},
				},
			},
			primaryAnnotation:   AppAnnotation,
			secondaryAnnotation: K8sRecommendedAppAnnotations,
			want:                "",
			want1:               false,
		},
		{
			name: "Test that empty string is returned when primary annotation cannot be found and secondary annotation is empty",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"some-other-annotation": "some-app-name",
					},
				},
			},
			primaryAnnotation:   AppAnnotation,
			secondaryAnnotation: "",
			want:                "",
			want1:               false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getLabelOrAnnotation(tt.pod, tt.primaryAnnotation, tt.secondaryAnnotation)
			if got != tt.want {
				t.Errorf("getLabelOrAnnotation() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getLabelOrAnnotation() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_getSpan_unbindSpan(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				WorkloadAnnotation: "myworkload",
				VersionAnnotation:  "0.0.1",
				AppAnnotation:      "myapp",
			},
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				WorkloadAnnotation: "myworkload",
				VersionAnnotation:  "0.0.2",
				AppAnnotation:      "myapp",
			},
		},
	}

	r := &WorkloadManager{
		bindCRDSpan: make(map[string]trace.Span, 100),
		Tracer:      trace.NewNoopTracerProvider().Tracer("trace"),
	}

	// create span for first pod
	_, span := r.getSpan(context.TODO(), &unstructured.Unstructured{}, pod)

	require.NotNil(t, span)
	require.Len(t, r.bindCRDSpan, 1)

	// fetch the created span for first pod
	_, span2 := r.getSpan(context.TODO(), &unstructured.Unstructured{}, pod)

	require.Equal(t, span, span2)
	require.Len(t, r.bindCRDSpan, 1)

	// create another span for second pod
	_, span3 := r.getSpan(context.TODO(), &unstructured.Unstructured{}, pod2)

	require.NotNil(t, span3)
	require.Len(t, r.bindCRDSpan, 2)

	// fetch the created span for second pod
	_, span4 := r.getSpan(context.TODO(), &unstructured.Unstructured{}, pod2)

	require.Equal(t, span3, span4)
	require.Len(t, r.bindCRDSpan, 2)

	// fetch the created span for first pod
	_, span5 := r.getSpan(context.TODO(), &unstructured.Unstructured{}, pod)

	require.Equal(t, span, span5)
	require.Len(t, r.bindCRDSpan, 2)

	// remove the created span for first pod
	r.unbindSpan(pod)
	require.Len(t, r.bindCRDSpan, 1)

	// fetch the span for second pod
	_, span6 := r.getSpan(context.TODO(), &unstructured.Unstructured{}, pod2)

	require.Equal(t, span3, span6)
	require.Len(t, r.bindCRDSpan, 1)

	// re-create span for first pod
	_, span7 := r.getSpan(context.TODO(), &unstructured.Unstructured{}, pod)

	require.Equal(t, span, span7)
	require.Len(t, r.bindCRDSpan, 2)

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
			name:          "empty pod",
			pod:           &corev1.Pod{},
			containerName: "",
			want:          "2166136261",
			wantErr:       false,
		},
		{
			name: "no containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
			},
			containerName: "",
			want:          "2166136261",
			wantErr:       false,
		},
		{
			name: "single container",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:tag",
						},
					},
				},
			},
			containerName: "",
			want:          "tag",
			wantErr:       false,
		},
		{
			name: "single container latest tag",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:latest",
						},
					},
				},
			},
			containerName: "",
			want:          "",
			wantErr:       true,
		},
		{
			name: "single container annotation mismatch",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:latest",
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
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:latest",
						},
						{
							Name:  "container-name2",
							Image: "image:latest2",
						},
					},
				},
			},
			containerName: "",
			want:          "3235658121",
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
		{
			name: "multiple containers with env",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pod-name",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container-name",
							Image: "image:latest",
							Env: []corev1.EnvVar{
								{
									Name:  "env1",
									Value: "value1",
								},
								{
									Name:  "env2",
									Value: "value2",
								},
							},
						},
						{
							Name:  "container-name2",
							Image: "image:latest2",
							Env: []corev1.EnvVar{
								{
									Name:  "env3",
									Value: "value3",
								},
								{
									Name:  "env4",
									Value: "value4",
								},
							},
						},
					},
				},
			},
			containerName: "",
			want:          "2484568705",
			wantErr:       false,
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

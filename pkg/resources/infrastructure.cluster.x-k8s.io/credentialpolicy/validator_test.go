package credentialpolicy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1api "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

// newTestAdmitter creates an admitter with the given store, getter, and a fake SAR client.
func newTestAdmitter(store *ConfigStore, getter objectGetter, sarAllowed bool) *admitter {
	fakeClient := fakeclientset.NewSimpleClientset()
	fakeClient.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1api.SubjectAccessReview{
			Status: authorizationv1api.SubjectAccessReviewStatus{
				Allowed: sarAllowed,
			},
		}, nil
	})

	return &admitter{
		store:  store,
		getter: getter,
		sar:    fakeClient.AuthorizationV1().SubjectAccessReviews(),
	}
}

func makeRequest(op admissionv1.Operation, gvr metav1.GroupVersionResource, namespace string, newObj, oldObj map[string]interface{}) *admission.Request {
	req := &admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "test-uid",
			Operation: op,
			Resource:  gvr,
			Namespace: namespace,
			UserInfo: authenticationv1.UserInfo{
				Username: "test-user",
				Groups:   []string{"system:authenticated"},
			},
		},
	}

	if newObj != nil {
		raw, _ := json.Marshal(newObj)
		req.Object = runtime.RawExtension{Raw: raw}
	}
	if oldObj != nil {
		raw, _ := json.Marshal(oldObj)
		req.OldObject = runtime.RawExtension{Raw: raw}
	}

	return req
}

func TestAdmitter_NoConfig_Allowed(t *testing.T) {
	store := NewConfigStore()
	a := newTestAdmitter(store, nil, false)

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "unknownresources"},
		"default",
		map[string]interface{}{"spec": map[string]interface{}{"foo": "bar"}},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestAdmitter_Create_Allowed(t *testing.T) {
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta1/gcpclusters": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.credentialsRef.name","namespaceField":"spec.credentialsRef.namespace"}]}`,
	})

	a := newTestAdmitter(store, nil, true) // SAR returns allowed

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "gcpclusters"},
		"fleet-default",
		map[string]interface{}{
			"spec": map[string]interface{}{
				"credentialsRef": map[string]interface{}{
					"name":      "gcp-creds",
					"namespace": "gcp-system",
				},
			},
		},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestAdmitter_Create_Denied(t *testing.T) {
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta1/gcpclusters": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.credentialsRef.name","namespaceField":"spec.credentialsRef.namespace"}]}`,
	})

	a := newTestAdmitter(store, nil, false) // SAR returns denied

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "gcpclusters"},
		"fleet-default",
		map[string]interface{}{
			"spec": map[string]interface{}{
				"credentialsRef": map[string]interface{}{
					"name":      "gcp-creds",
					"namespace": "gcp-system",
				},
			},
		},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.False(t, resp.Allowed)
	assert.Contains(t, resp.Result.Message, "does not have permission to get secret")
	assert.Contains(t, resp.Result.Message, "gcp-system/gcp-creds")
}

func TestAdmitter_Update_SkipsWhenRefUnchanged(t *testing.T) {
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta1/gcpclusters": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.credentialsRef.name","namespaceField":"spec.credentialsRef.namespace"}]}`,
	})

	// SAR returns denied - but it should never be called because ref is unchanged
	a := newTestAdmitter(store, nil, false)

	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"credentialsRef": map[string]interface{}{
				"name":      "gcp-creds",
				"namespace": "gcp-system",
			},
		},
	}

	request := makeRequest(
		admissionv1.Update,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "gcpclusters"},
		"fleet-default",
		obj,
		obj, // same as new - no change
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestAdmitter_Update_DeniedWhenRefChanged(t *testing.T) {
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta1/gcpclusters": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.credentialsRef.name","namespaceField":"spec.credentialsRef.namespace"}]}`,
	})

	a := newTestAdmitter(store, nil, false) // SAR returns denied

	oldObj := map[string]interface{}{
		"spec": map[string]interface{}{
			"credentialsRef": map[string]interface{}{
				"name":      "old-creds",
				"namespace": "gcp-system",
			},
		},
	}
	newObj := map[string]interface{}{
		"spec": map[string]interface{}{
			"credentialsRef": map[string]interface{}{
				"name":      "new-creds",
				"namespace": "gcp-system",
			},
		},
	}

	request := makeRequest(
		admissionv1.Update,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "gcpclusters"},
		"fleet-default",
		newObj,
		oldObj,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.False(t, resp.Allowed)
	assert.Contains(t, resp.Result.Message, "does not have permission to get secret")
}

func TestAdmitter_EmptyCredentialRefs_Allowed(t *testing.T) {
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclustercontrolleridentities": `{"credentialRefs":[]}`,
	})

	a := newTestAdmitter(store, nil, false)

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclustercontrolleridentities"},
		"",
		map[string]interface{}{"spec": map[string]interface{}{}},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestAdmitter_OptionalRefEmpty_Allowed(t *testing.T) {
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta1/azureclusteridentities": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.clientSecret.name","namespaceField":"spec.clientSecret.namespace"}]}`,
	})

	a := newTestAdmitter(store, nil, false) // SAR denied, but won't be called

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "azureclusteridentities"},
		"default",
		map[string]interface{}{
			"spec": map[string]interface{}{
				"clientSecret": map[string]interface{}{
					"name":      "",
					"namespace": "",
				},
			},
		},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestAdmitter_ThreeLevelChain_AWS(t *testing.T) {
	// AWSCluster -> AWSClusterRoleIdentity -> AWSClusterStaticIdentity -> Secret
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters":                `{"credentialRefs":[{"kindField":"spec.identityRef.kind","nameField":"spec.identityRef.name"}]}`,
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterroleidentities":   `{"credentialRefs":[{"kindField":"spec.sourceIdentityRef.kind","nameField":"spec.sourceIdentityRef.name"}]}`,
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticidentities": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.secretRef","namespace":"capa-system"}]}`,
	})

	roleIdentity := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSClusterRoleIdentity",
			"metadata":   map[string]interface{}{"name": "my-role-id"},
			"spec": map[string]interface{}{
				"sourceIdentityRef": map[string]interface{}{
					"kind": "AWSClusterStaticIdentity",
					"name": "my-static-id",
				},
			},
		},
	}

	staticIdentity := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSClusterStaticIdentity",
			"metadata":   map[string]interface{}{"name": "my-static-id"},
			"spec": map[string]interface{}{
				"secretRef": "aws-credentials",
			},
		},
	}

	getter := &mockObjectGetter{
		objects: map[string]*unstructured.Unstructured{
			"infrastructure.cluster.x-k8s.io/AWSClusterRoleIdentity//my-role-id":     roleIdentity,
			"infrastructure.cluster.x-k8s.io/AWSClusterStaticIdentity//my-static-id": staticIdentity,
		},
	}

	a := newTestAdmitter(store, getter, true) // SAR allowed

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"},
		"fleet-default",
		map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSCluster",
			"spec": map[string]interface{}{
				"identityRef": map[string]interface{}{
					"kind": "AWSClusterRoleIdentity",
					"name": "my-role-id",
				},
			},
		},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestAdmitter_ThreeLevelChain_AWS_Denied(t *testing.T) {
	// Same as above but SAR denied
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters":                `{"credentialRefs":[{"kindField":"spec.identityRef.kind","nameField":"spec.identityRef.name"}]}`,
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterroleidentities":   `{"credentialRefs":[{"kindField":"spec.sourceIdentityRef.kind","nameField":"spec.sourceIdentityRef.name"}]}`,
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticidentities": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.secretRef","namespace":"capa-system"}]}`,
	})

	roleIdentity := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSClusterRoleIdentity",
			"metadata":   map[string]interface{}{"name": "my-role-id"},
			"spec": map[string]interface{}{
				"sourceIdentityRef": map[string]interface{}{
					"kind": "AWSClusterStaticIdentity",
					"name": "my-static-id",
				},
			},
		},
	}

	staticIdentity := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSClusterStaticIdentity",
			"metadata":   map[string]interface{}{"name": "my-static-id"},
			"spec": map[string]interface{}{
				"secretRef": "aws-credentials",
			},
		},
	}

	getter := &mockObjectGetter{
		objects: map[string]*unstructured.Unstructured{
			"infrastructure.cluster.x-k8s.io/AWSClusterRoleIdentity//my-role-id":     roleIdentity,
			"infrastructure.cluster.x-k8s.io/AWSClusterStaticIdentity//my-static-id": staticIdentity,
		},
	}

	a := newTestAdmitter(store, getter, false) // SAR denied

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"},
		"fleet-default",
		map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSCluster",
			"spec": map[string]interface{}{
				"identityRef": map[string]interface{}{
					"kind": "AWSClusterRoleIdentity",
					"name": "my-role-id",
				},
			},
		},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.False(t, resp.Allowed)
	assert.Contains(t, resp.Result.Message, "does not have permission to get secret")
	assert.Contains(t, resp.Result.Message, "capa-system/aws-credentials")
}

func TestAdmitter_ControllerIdentity_Skip(t *testing.T) {
	// AWSCluster -> AWSClusterControllerIdentity (empty credentialRefs -> skip)
	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters":                       `{"credentialRefs":[{"kindField":"spec.identityRef.kind","nameField":"spec.identityRef.name"}]}`,
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclustercontrolleridentities": `{"credentialRefs":[]}`,
	})

	controllerIdentity := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSClusterControllerIdentity",
			"metadata":   map[string]interface{}{"name": "default"},
			"spec":       map[string]interface{}{},
		},
	}

	getter := &mockObjectGetter{
		objects: map[string]*unstructured.Unstructured{
			"infrastructure.cluster.x-k8s.io/AWSClusterControllerIdentity//default": controllerIdentity,
		},
	}

	a := newTestAdmitter(store, getter, false) // SAR denied, but shouldn't be called

	request := makeRequest(
		admissionv1.Create,
		metav1.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"},
		"fleet-default",
		map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSCluster",
			"spec": map[string]interface{}{
				"identityRef": map[string]interface{}{
					"kind": "AWSClusterControllerIdentity",
					"name": "default",
				},
			},
		},
		nil,
	)

	resp, err := a.Admit(request)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

// Ensure the Validator satisfies the interface
var _ admission.ValidatingAdmissionHandler = &Validator{}

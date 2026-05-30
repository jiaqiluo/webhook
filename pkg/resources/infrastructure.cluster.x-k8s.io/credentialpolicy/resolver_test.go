package credentialpolicy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestResolveField(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"identityRef": map[string]interface{}{
					"kind": "AWSClusterStaticIdentity",
					"name": "my-identity",
				},
				"secretRef": "my-secret",
				"credentialsRef": map[string]interface{}{
					"namespace": "default",
					"name":      "gcp-creds",
				},
			},
		},
	}

	tests := []struct {
		name     string
		literal  string
		field    string
		expected string
	}{
		{name: "literal wins", literal: "hardcoded", field: "", expected: "hardcoded"},
		{name: "field path nested map", literal: "", field: "spec.identityRef.kind", expected: "AWSClusterStaticIdentity"},
		{name: "field path string value", literal: "", field: "spec.secretRef", expected: "my-secret"},
		{name: "field path deep", literal: "", field: "spec.credentialsRef.name", expected: "gcp-creds"},
		{name: "field path not found", literal: "", field: "spec.nonexistent.field", expected: ""},
		{name: "both empty", literal: "", field: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveField(tt.literal, tt.field, obj)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestResolveField_NilObject(t *testing.T) {
	got := resolveField("literal", "", nil)
	assert.Equal(t, "literal", got)

	got = resolveField("", "spec.foo", nil)
	assert.Equal(t, "", got)
}

// mockObjectGetter implements objectGetter for testing.
type mockObjectGetter struct {
	objects map[string]*unstructured.Unstructured
}

func (m *mockObjectGetter) Get(gvk schema.GroupVersionKind, namespace, name string) (*unstructured.Unstructured, error) {
	key := fmt.Sprintf("%s/%s/%s/%s", gvk.Group, gvk.Kind, namespace, name)
	obj, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("not found: %s", key)
	}
	return obj, nil
}

func TestTraverseCredentialChain_DirectSecret(t *testing.T) {
	// GCPCluster -> Secret directly
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"credentialsRef": map[string]interface{}{
					"name":      "gcp-creds",
					"namespace": "default",
				},
			},
		},
	}
	policy := &CredentialPolicy{CredentialRefs: []CredentialRef{
		{Kind: "Secret", NameField: "spec.credentialsRef.name", NamespaceField: "spec.credentialsRef.namespace"},
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "gcpclusters"}

	result := TraverseCredentialChain(obj, gvr, policy, NewConfigStore(), nil, "fleet-default")

	require.NoError(t, result.err)
	assert.False(t, result.skip)
	assert.Equal(t, "gcp-creds", result.secretName)
	assert.Equal(t, "default", result.secretNamespace)
}

func TestTraverseCredentialChain_SecretNamespaceDefaultsToObjectNamespace(t *testing.T) {
	// VSphereCluster -> Secret (no namespace in ref, uses object namespace)
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"identityRef": map[string]interface{}{
					"kind": "Secret",
					"name": "vsphere-creds",
				},
			},
		},
	}
	policy := &CredentialPolicy{CredentialRefs: []CredentialRef{
		{KindField: "spec.identityRef.kind", NameField: "spec.identityRef.name"},
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "vsphereclusters"}

	result := TraverseCredentialChain(obj, gvr, policy, NewConfigStore(), nil, "fleet-default")

	require.NoError(t, result.err)
	assert.Equal(t, "vsphere-creds", result.secretName)
	assert.Equal(t, "fleet-default", result.secretNamespace)
}

func TestTraverseCredentialChain_TwoLevelIdentityToSecret(t *testing.T) {
	// AWSCluster -> AWSClusterStaticIdentity -> Secret
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"identityRef": map[string]interface{}{
					"kind": "AWSClusterStaticIdentity",
					"name": "my-static-id",
				},
			},
		},
	}

	identityObj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSClusterStaticIdentity",
			"metadata":   map[string]interface{}{"name": "my-static-id"},
			"spec": map[string]interface{}{
				"secretRef": "aws-creds",
			},
		},
	}

	getter := &mockObjectGetter{
		objects: map[string]*unstructured.Unstructured{
			"infrastructure.cluster.x-k8s.io/AWSClusterStaticIdentity//my-static-id": identityObj,
		},
	}

	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticidentities": `{"credentialRefs":[{"kind":"Secret","nameField":"spec.secretRef","namespace":"capa-system"}]}`,
	})

	policy := &CredentialPolicy{CredentialRefs: []CredentialRef{
		{KindField: "spec.identityRef.kind", NameField: "spec.identityRef.name"},
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"}

	result := TraverseCredentialChain(obj, gvr, policy, store, getter, "fleet-default")

	require.NoError(t, result.err)
	assert.False(t, result.skip)
	assert.Equal(t, "aws-creds", result.secretName)
	assert.Equal(t, "capa-system", result.secretNamespace)
}

func TestTraverseCredentialChain_EmptyNameSkips(t *testing.T) {
	// AzureClusterIdentity with WorkloadIdentity (clientSecret is empty)
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"clientSecret": map[string]interface{}{
					"name":      "",
					"namespace": "",
				},
			},
		},
	}
	policy := &CredentialPolicy{CredentialRefs: []CredentialRef{
		{Kind: "Secret", NameField: "spec.clientSecret.name", NamespaceField: "spec.clientSecret.namespace"},
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "azureclusteridentities"}

	result := TraverseCredentialChain(obj, gvr, policy, NewConfigStore(), nil, "default")

	assert.True(t, result.skip)
	assert.NoError(t, result.err)
}

func TestTraverseCredentialChain_IdentityNotFound(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"identityRef": map[string]interface{}{
					"kind": "AWSClusterStaticIdentity",
					"name": "nonexistent",
				},
			},
		},
	}
	policy := &CredentialPolicy{CredentialRefs: []CredentialRef{
		{KindField: "spec.identityRef.kind", NameField: "spec.identityRef.name"},
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"}

	getter := &mockObjectGetter{objects: map[string]*unstructured.Unstructured{}}

	result := TraverseCredentialChain(obj, gvr, policy, NewConfigStore(), getter, "fleet-default")

	require.Error(t, result.err)
	assert.Contains(t, result.err.Error(), "not found")
}

func TestTraverseCredentialChain_CircularReference(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"sourceIdentityRef": map[string]interface{}{
					"kind": "AWSClusterRoleIdentity",
					"name": "role-a",
				},
			},
		},
	}

	roleA := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta2",
			"kind":       "AWSClusterRoleIdentity",
			"metadata":   map[string]interface{}{"name": "role-a"},
			"spec": map[string]interface{}{
				"sourceIdentityRef": map[string]interface{}{
					"kind": "AWSClusterRoleIdentity",
					"name": "role-a",
				},
			},
		},
	}

	getter := &mockObjectGetter{
		objects: map[string]*unstructured.Unstructured{
			"infrastructure.cluster.x-k8s.io/AWSClusterRoleIdentity//role-a": roleA,
		},
	}

	store := NewConfigStore()
	store.UpdateConfigMap(map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterroleidentities": `{"credentialRefs":[{"kindField":"spec.sourceIdentityRef.kind","nameField":"spec.sourceIdentityRef.name"}]}`,
	})

	policy := &CredentialPolicy{CredentialRefs: []CredentialRef{
		{KindField: "spec.sourceIdentityRef.kind", NameField: "spec.sourceIdentityRef.name"},
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusterroleidentities"}

	result := TraverseCredentialChain(obj, gvr, policy, store, getter, "")

	require.Error(t, result.err)
	assert.Contains(t, result.err.Error(), "circular credential reference")
}

func TestTraverseCredentialChain_NilPolicy(t *testing.T) {
	result := TraverseCredentialChain(nil, schema.GroupVersionResource{}, nil, NewConfigStore(), nil, "")
	assert.True(t, result.skip)
}

func TestGvrFromGVK(t *testing.T) {
	tests := []struct {
		name     string
		gvk      schema.GroupVersionKind
		expected schema.GroupVersionResource
	}{
		{
			name: "identity ending in y",
			gvk:  schema.GroupVersionKind{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSClusterStaticIdentity"},
			expected: schema.GroupVersionResource{
				Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusterstaticidentities",
			},
		},
		{
			name: "cluster ending in r",
			gvk:  schema.GroupVersionKind{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSCluster"},
			expected: schema.GroupVersionResource{
				Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gvrFromGVK(tt.gvk)
			assert.Equal(t, tt.expected, got)
		})
	}
}

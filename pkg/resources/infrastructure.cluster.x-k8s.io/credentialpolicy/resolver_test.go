package credentialpolicy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestResolveValue(t *testing.T) {
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
		value    string
		expected string
		wantErr  string
	}{
		{name: "literal value", value: "Secret", expected: "Secret"},
		{name: "literal apiVersion", value: "infrastructure.cluster.x-k8s.io/v1beta2", expected: "infrastructure.cluster.x-k8s.io/v1beta2"},
		{name: "dot-path nested map", value: ".spec.identityRef.kind", expected: "AWSClusterStaticIdentity"},
		{name: "dot-path identity name", value: ".spec.identityRef.name", expected: "my-identity"},
		{name: "dot-path string leaf", value: ".spec.secretRef", expected: "my-secret"},
		{name: "dot-path deep", value: ".spec.credentialsRef.name", expected: "gcp-creds"},
		{name: "dot-path not found", value: ".spec.nonexistent.field", expected: ""},
		{name: "empty string", value: "", expected: ""},
		{name: "jsonpath simple field", value: "$.spec.identityRef.kind", expected: "AWSClusterStaticIdentity"},
		{name: "jsonpath string leaf", value: "$.spec.secretRef", expected: "my-secret"},
		{name: "jsonpath deep", value: "$.spec.credentialsRef.name", expected: "gcp-creds"},
		{name: "jsonpath not found returns empty", value: "$.spec.nonexistent.field", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveValue(tt.value, obj)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestResolveValue_NilObject(t *testing.T) {
	// Literals work without an object
	got, err := resolveValue("Secret", nil)
	require.NoError(t, err)
	assert.Equal(t, "Secret", got)

	// Dot-path with nil object returns empty
	got, err = resolveValue(".spec.foo", nil)
	require.NoError(t, err)
	assert.Equal(t, "", got)

	// JSONPath with nil object returns empty
	got, err = resolveValue("$.spec.foo", nil)
	require.NoError(t, err)
	assert.Equal(t, "", got)

	// Empty value returns empty
	got, err = resolveValue("", nil)
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

func TestResolveValue_JSONPath_ArrayIndex(t *testing.T) {
	// JSONPath can index into arrays — the key capability dot-path lacks
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"versions": []interface{}{
					map[string]interface{}{"name": "v1alpha1", "storage": false},
					map[string]interface{}{"name": "v1beta2", "storage": true},
				},
			},
		},
	}

	got, err := resolveValue("$.spec.versions[1].name", obj)
	require.NoError(t, err)
	assert.Equal(t, "v1beta2", got)
}

func TestResolveValue_JSONPath_InvalidExpression(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	_, err := resolveValue("$.[[[invalid", obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JSONPath")
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
	policy := &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: "Secret", Name: ".spec.credentialsRef.name", Namespace: ".spec.credentialsRef.namespace",
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "gcpclusters"}

	result := traverseCredentialChain(obj, gvr, policy, NewConfigStore(), nil, "fleet-default")

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
	policy := &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: ".spec.identityRef.kind", Name: ".spec.identityRef.name",
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "vsphereclusters"}

	result := traverseCredentialChain(obj, gvr, policy, NewConfigStore(), nil, "fleet-default")

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
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticidentities": `{"credentialRef":{"kind":"Secret","name":".spec.secretRef","namespace":"capa-system"}}`,
	})

	policy := &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: ".spec.identityRef.kind", Name: ".spec.identityRef.name",
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"}

	result := traverseCredentialChain(obj, gvr, policy, store, getter, "fleet-default")

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
	policy := &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: "Secret", Name: ".spec.clientSecret.name", Namespace: ".spec.clientSecret.namespace",
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "azureclusteridentities"}

	result := traverseCredentialChain(obj, gvr, policy, NewConfigStore(), nil, "default")

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
	policy := &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: ".spec.identityRef.kind", Name: ".spec.identityRef.name",
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"}

	getter := &mockObjectGetter{objects: map[string]*unstructured.Unstructured{}}

	result := traverseCredentialChain(obj, gvr, policy, NewConfigStore(), getter, "fleet-default")

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
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterroleidentities": `{"credentialRef":{"kind":".spec.sourceIdentityRef.kind","name":".spec.sourceIdentityRef.name"}}`,
	})

	policy := &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: ".spec.sourceIdentityRef.kind", Name: ".spec.sourceIdentityRef.name",
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusterroleidentities"}

	result := traverseCredentialChain(obj, gvr, policy, store, getter, "")

	require.Error(t, result.err)
	assert.Contains(t, result.err.Error(), "circular credential reference")
}

func TestTraverseCredentialChain_NilPolicy(t *testing.T) {
	result := traverseCredentialChain(nil, schema.GroupVersionResource{}, nil, NewConfigStore(), nil, "")
	assert.True(t, result.skip)
}

func TestTraverseCredentialChain_JSONPathError(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{"name": "foo"},
		},
	}
	policy := &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: "Secret", Name: "$.[[[invalid",
	}}
	gvr := schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"}

	result := traverseCredentialChain(obj, gvr, policy, NewConfigStore(), nil, "default")

	require.Error(t, result.err)
	assert.Contains(t, result.err.Error(), "failed to parse JSONPath")
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

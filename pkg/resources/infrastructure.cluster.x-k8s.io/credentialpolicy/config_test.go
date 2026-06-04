package credentialpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	awsClusterGVR = schema.GroupVersionResource{
		Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters",
	}
	awsStaticIdentityGVR = schema.GroupVersionResource{
		Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusterstaticidentities",
	}
	unknownGVR = schema.GroupVersionResource{
		Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "unknownresources",
	}
)

func TestConfigStore_GetPolicy_ConfigMapPrecedence(t *testing.T) {
	store := NewConfigStore()
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters": `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	})
	store.UpdateCRDAnnotation(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		awsClusterGVR,
		`{"credentialRef":{"kind":"Secret","name":".spec.other"}}`,
	)

	got := store.GetPolicy(awsClusterGVR)
	require.NotNil(t, got)
	assert.Equal(t, &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: ".spec.identityRef.kind", Name: ".spec.identityRef.name",
	}}, got)
}

func TestConfigStore_GetPolicy_FallbackToAnnotation(t *testing.T) {
	store := NewConfigStore()
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{})
	store.UpdateCRDAnnotation(
		"awsclusterstaticidentities.infrastructure.cluster.x-k8s.io",
		awsStaticIdentityGVR,
		`{"credentialRef":{"kind":"Secret","name":".spec.secretRef","namespace":"capa-system"}}`,
	)

	got := store.GetPolicy(awsStaticIdentityGVR)
	require.NotNil(t, got)
	assert.Equal(t, &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: "Secret", Name: ".spec.secretRef", Namespace: "capa-system",
	}}, got)
}

func TestConfigStore_GetPolicy_NilWhenUnconfigured(t *testing.T) {
	store := NewConfigStore()
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{})
	assert.Nil(t, store.GetPolicy(unknownGVR))
}

func TestConfigStore_DeleteConfigMap(t *testing.T) {
	store := NewConfigStore()
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters": `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	})
	require.NotNil(t, store.GetPolicy(awsClusterGVR))

	store.DeleteConfigMap("capa-system", "credential-policies")
	assert.Nil(t, store.GetPolicy(awsClusterGVR))
}

func TestConfigStore_DeleteCRDAnnotation(t *testing.T) {
	store := NewConfigStore()
	store.UpdateCRDAnnotation(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		awsClusterGVR,
		`{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	)
	require.NotNil(t, store.GetPolicy(awsClusterGVR))

	store.DeleteCRDAnnotation("awsclusters.infrastructure.cluster.x-k8s.io")
	assert.Nil(t, store.GetPolicy(awsClusterGVR))
}

func TestConfigStore_DeleteCRDAnnotation_UnknownName_NoOp(_ *testing.T) {
	store := NewConfigStore()
	// Must not panic
	store.DeleteCRDAnnotation("nonexistent.crd")
}

func TestConfigStore_PerCM_TwoProviders(t *testing.T) {
	store := NewConfigStore()
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters": `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	})
	vsphereGVR := schema.GroupVersionResource{
		Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta1", Resource: "vsphereclusters",
	}
	store.UpdateFromConfigMap("capv-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta1/vsphereclusters": `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	})

	assert.NotNil(t, store.GetPolicy(awsClusterGVR))
	assert.NotNil(t, store.GetPolicy(vsphereGVR))

	store.DeleteConfigMap("capa-system", "credential-policies")
	assert.Nil(t, store.GetPolicy(awsClusterGVR))
	assert.NotNil(t, store.GetPolicy(vsphereGVR))
}

func TestConfigStore_UpdateFromConfigMap_InvalidEntrySkipped(t *testing.T) {
	store := NewConfigStore()
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters":         `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticids": `{not-valid-json}`,
	})

	assert.NotNil(t, store.GetPolicy(awsClusterGVR))
	assert.Nil(t, store.GetPolicy(schema.GroupVersionResource{
		Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusterstaticids",
	}))
}

func TestConfigStore_UpdateCRDAnnotation_Remove(t *testing.T) {
	store := NewConfigStore()
	store.UpdateCRDAnnotation(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		awsClusterGVR,
		`{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	)
	require.NotNil(t, store.GetPolicy(awsClusterGVR))

	store.UpdateCRDAnnotation("awsclusters.infrastructure.cluster.x-k8s.io", awsClusterGVR, "")
	assert.Nil(t, store.GetPolicy(awsClusterGVR))
}

func TestConfigStore_ConflictWarnedAtWriteTime(t *testing.T) {
	// Two CMs define the same GVR; alphabetically earlier key wins.
	store := NewConfigStore()
	store.UpdateFromConfigMap("aaa-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters": `{"credentialRef":{"kind":"Secret","name":".spec.aaa"}}`,
	})
	// zzz-system/credential-policies arrives second but loses alphabetically.
	store.UpdateFromConfigMap("zzz-system", "credential-policies", map[string]string{
		"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters": `{"credentialRef":{"kind":"Secret","name":".spec.zzz"}}`,
	})

	got := store.GetPolicy(awsClusterGVR)
	require.NotNil(t, got)
	assert.Equal(t, ".spec.aaa", got.CredentialRef.Name)
}

func TestConfigStore_ConfigMapKeys(t *testing.T) {
	store := NewConfigStore()
	store.UpdateFromConfigMap("capa-system", "credential-policies", map[string]string{})
	store.UpdateFromConfigMap("capv-system", "credential-policies", map[string]string{})

	keys := store.configMapKeys()
	assert.Equal(t, []string{"capa-system/credential-policies", "capv-system/credential-policies"}, keys)
}

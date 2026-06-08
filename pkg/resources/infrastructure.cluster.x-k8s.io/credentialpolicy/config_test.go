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

func TestConfigStore_GetPolicy_ReturnsAnnotation(t *testing.T) {
	store := NewConfigStore()
	store.UpdateCRDAnnotation(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		awsClusterGVR,
		`{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	)

	got := store.GetPolicy(awsClusterGVR)
	require.NotNil(t, got)
	assert.Equal(t, &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: ".spec.identityRef.kind", Name: ".spec.identityRef.name",
	}}, got)
}

func TestConfigStore_GetPolicy_NilWhenUnconfigured(t *testing.T) {
	store := NewConfigStore()
	assert.Nil(t, store.GetPolicy(unknownGVR))
}

func TestConfigStore_GetPolicy_TwoGVRs(t *testing.T) {
	store := NewConfigStore()
	store.UpdateCRDAnnotation(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		awsClusterGVR,
		`{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
	)
	store.UpdateCRDAnnotation(
		"awsclusterstaticidentities.infrastructure.cluster.x-k8s.io",
		awsStaticIdentityGVR,
		`{"credentialRef":{"kind":"Secret","name":".spec.secretRef","namespace":"capa-system"}}`,
	)

	assert.NotNil(t, store.GetPolicy(awsClusterGVR))
	assert.NotNil(t, store.GetPolicy(awsStaticIdentityGVR))
	assert.Nil(t, store.GetPolicy(unknownGVR))
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

package credentialpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// makeCRD builds a minimal typed CRD for use in tests.
func makeCRD(name, group, plural, version string, annotations map[string]string) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: group,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural: plural,
			},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: version, Served: true, Storage: true},
			},
		},
	}
}

var capaAWSClusterGVR = schema.GroupVersionResource{
	Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters",
}

// --- OnCRDChange ---

func TestOnCRDChange_LoadsAnnotation(t *testing.T) {
	store := NewConfigStore()
	crd := makeCRD(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		"infrastructure.cluster.x-k8s.io",
		"awsclusters", "v1beta2",
		map[string]string{
			AnnotationKey: `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
		},
	)

	OnCRDChange(store, crd)

	got := store.GetPolicy(capaAWSClusterGVR)
	require.NotNil(t, got)
	assert.Equal(t, &CredentialPolicy{CredentialRef: CredentialRef{
		Kind: ".spec.identityRef.kind", Name: ".spec.identityRef.name",
	}}, got)
}

func TestOnCRDChange_WrongGroup_Skipped(t *testing.T) {
	store := NewConfigStore()
	crd := makeCRD(
		"foos.other.group", "other.group", "foos", "v1",
		map[string]string{
			AnnotationKey: `{"credentialRef":{"kind":"Secret","name":".spec.foo"}}`,
		},
	)

	OnCRDChange(store, crd)

	assert.Nil(t, store.GetPolicy(schema.GroupVersionResource{
		Group: "other.group", Version: "v1", Resource: "foos",
	}))
}

func TestOnCRDChange_NoAnnotation_ClearsExistingEntry(t *testing.T) {
	store := NewConfigStore()
	// Seed with annotation
	crd := makeCRD(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		"infrastructure.cluster.x-k8s.io",
		"awsclusters", "v1beta2",
		map[string]string{
			AnnotationKey: `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
		},
	)
	OnCRDChange(store, crd)
	require.NotNil(t, store.GetPolicy(capaAWSClusterGVR))

	// Update without annotation — should clear the entry
	crdNoAnnotation := makeCRD(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		"infrastructure.cluster.x-k8s.io",
		"awsclusters", "v1beta2", nil,
	)
	OnCRDChange(store, crdNoAnnotation)

	assert.Nil(t, store.GetPolicy(capaAWSClusterGVR))
}

func TestOnCRDChange_Nil_NoOp(_ *testing.T) {
	store := NewConfigStore()
	// Must not panic
	OnCRDChange(store, nil)
}

func TestOnCRDChange_DeletingCRD_Ignored(t *testing.T) {
	store := NewConfigStore()
	crd := makeCRD(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		"infrastructure.cluster.x-k8s.io",
		"awsclusters", "v1beta2",
		map[string]string{
			AnnotationKey: `{"credentialRef":{"kind":"Secret","name":".spec.secretRef"}}`,
		},
	)
	now := metav1.Now()
	crd.DeletionTimestamp = &now

	OnCRDChange(store, crd)

	assert.Nil(t, store.GetPolicy(capaAWSClusterGVR))
}

func TestOnCRDChange_NoPluralName_Skipped(t *testing.T) {
	store := NewConfigStore()
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "awsclusters.infrastructure.cluster.x-k8s.io",
			Annotations: map[string]string{
				AnnotationKey: `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "infrastructure.cluster.x-k8s.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: ""},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: "v1beta2", Served: true, Storage: true},
			},
		},
	}

	OnCRDChange(store, crd)

	assert.Nil(t, store.GetPolicy(capaAWSClusterGVR))
}

func TestOnCRDChange_NoServedVersions_Skipped(t *testing.T) {
	store := NewConfigStore()
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "awsclusters.infrastructure.cluster.x-k8s.io",
			Annotations: map[string]string{
				AnnotationKey: `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "infrastructure.cluster.x-k8s.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: "awsclusters"},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: "v1beta1", Served: false, Storage: false},
			},
		},
	}

	OnCRDChange(store, crd)

	assert.Nil(t, store.GetPolicy(capaAWSClusterGVR))
}

// --- OnCRDDelete ---

func TestOnCRDDelete_ClearsEntry(t *testing.T) {
	store := NewConfigStore()
	crd := makeCRD(
		"awsclusters.infrastructure.cluster.x-k8s.io",
		"infrastructure.cluster.x-k8s.io",
		"awsclusters", "v1beta2",
		map[string]string{
			AnnotationKey: `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
		},
	)
	OnCRDChange(store, crd)
	require.NotNil(t, store.GetPolicy(capaAWSClusterGVR))

	OnCRDDelete(store, "awsclusters.infrastructure.cluster.x-k8s.io")

	assert.Nil(t, store.GetPolicy(capaAWSClusterGVR))
}

func TestOnCRDDelete_UnknownName_NoOp(_ *testing.T) {
	store := NewConfigStore()
	// Must not panic
	OnCRDDelete(store, "nonexistent.crd")
}

// --- servingVersion ---

func TestServingVersion_StorageAndServed(t *testing.T) {
	crd := makeCRD("x", "g", "xs", "v1beta2", nil)
	assert.Equal(t, "v1beta2", servingVersion(crd))
}

func TestServingVersion_FirstServedWhenNoStorage(t *testing.T) {
	crd := &apiextensionsv1.CustomResourceDefinition{
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: "v1alpha1", Served: true, Storage: false},
				{Name: "v1beta1", Served: true, Storage: false},
			},
		},
	}
	assert.Equal(t, "v1alpha1", servingVersion(crd))
}

func TestServingVersion_NoneServed(t *testing.T) {
	crd := &apiextensionsv1.CustomResourceDefinition{
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: "v1alpha1", Served: false, Storage: false},
			},
		},
	}
	assert.Equal(t, "", servingVersion(crd))
}

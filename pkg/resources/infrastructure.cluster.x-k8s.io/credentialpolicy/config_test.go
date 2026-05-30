package credentialpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestConfigStore_GetPolicy(t *testing.T) {
	tests := []struct {
		name          string
		configMapData map[string]string
		crdAnnotation string
		gvr           schema.GroupVersionResource
		want          *CredentialPolicy
	}{
		{
			name: "configmap takes precedence over annotation",
			configMapData: map[string]string{
				"infrastructure.cluster.x-k8s.io/v1beta2/awsclusters": `{"credentialRefs":[{"kindField":"spec.identityRef.kind","nameField":"spec.identityRef.name"}]}`,
			},
			crdAnnotation: `{"credentialRefs":[{"kind":"Secret","nameField":"spec.other"}]}`,
			gvr:           schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusters"},
			want:          &CredentialPolicy{CredentialRefs: []CredentialRef{{KindField: "spec.identityRef.kind", NameField: "spec.identityRef.name"}}},
		},
		{
			name:          "falls back to annotation when configmap has no entry",
			configMapData: map[string]string{},
			crdAnnotation: `{"credentialRefs":[{"kind":"Secret","nameField":"spec.secretRef","namespace":"capa-system"}]}`,
			gvr:           schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclusterstaticidentities"},
			want:          &CredentialPolicy{CredentialRefs: []CredentialRef{{Kind: "Secret", NameField: "spec.secretRef", Namespace: "capa-system"}}},
		},
		{
			name:          "no config anywhere returns nil",
			configMapData: map[string]string{},
			crdAnnotation: "",
			gvr:           schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "unknownresources"},
			want:          nil,
		},
		{
			name: "empty credentialRefs in configmap returns policy with empty slice",
			configMapData: map[string]string{
				"infrastructure.cluster.x-k8s.io/v1beta2/awsclustercontrolleridentities": `{"credentialRefs":[]}`,
			},
			crdAnnotation: "",
			gvr:           schema.GroupVersionResource{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Resource: "awsclustercontrolleridentities"},
			want:          &CredentialPolicy{CredentialRefs: []CredentialRef{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewConfigStore()
			store.UpdateConfigMap(tt.configMapData)

			if tt.crdAnnotation != "" {
				store.UpdateCRDAnnotation(tt.gvr, tt.crdAnnotation)
			}

			got := store.GetPolicy(tt.gvr)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

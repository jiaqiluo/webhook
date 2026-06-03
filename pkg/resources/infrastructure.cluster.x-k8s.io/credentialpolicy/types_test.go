package credentialpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCredentialPolicy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *CredentialPolicy
		wantErr string
	}{
		{
			name:  "empty string returns nil",
			input: "",
			want:  nil,
		},
		{
			name:  "dot-path name and kind",
			input: `{"credentialRef":{"kind":".spec.identityRef.kind","name":".spec.identityRef.name"}}`,
			want: &CredentialPolicy{CredentialRef: CredentialRef{
				Kind: ".spec.identityRef.kind", Name: ".spec.identityRef.name",
			}},
		},
		{
			name:  "literal kind and dot-path name with literal namespace",
			input: `{"credentialRef":{"kind":"Secret","name":".spec.secretRef","namespace":"capa-system"}}`,
			want: &CredentialPolicy{CredentialRef: CredentialRef{
				Kind: "Secret", Name: ".spec.secretRef", Namespace: "capa-system",
			}},
		},
		{
			name:  "all literals",
			input: `{"credentialRef":{"kind":"Secret","name":"my-secret","namespace":"my-ns"}}`,
			want: &CredentialPolicy{CredentialRef: CredentialRef{
				Kind: "Secret", Name: "my-secret", Namespace: "my-ns",
			}},
		},
		{
			name:    "missing name",
			input:   `{"credentialRef":{"kind":"Secret"}}`,
			wantErr: "name is required",
		},
		{
			name:    "invalid JSON",
			input:   `{not json}`,
			wantErr: "failed to parse credential policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialPolicy(tt.input)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

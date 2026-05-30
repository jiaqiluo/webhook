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
			name:  "empty credentialRefs",
			input: `{"credentialRefs":[]}`,
			want:  &CredentialPolicy{CredentialRefs: []CredentialRef{}},
		},
		{
			name:  "valid with nameField only",
			input: `{"credentialRefs":[{"kindField":"spec.identityRef.kind","nameField":"spec.identityRef.name"}]}`,
			want: &CredentialPolicy{CredentialRefs: []CredentialRef{
				{KindField: "spec.identityRef.kind", NameField: "spec.identityRef.name"},
			}},
		},
		{
			name:  "valid with literals",
			input: `{"credentialRefs":[{"kind":"Secret","nameField":"spec.secretRef","namespace":"capa-system"}]}`,
			want: &CredentialPolicy{CredentialRefs: []CredentialRef{
				{Kind: "Secret", NameField: "spec.secretRef", Namespace: "capa-system"},
			}},
		},
		{
			name:    "both name and nameField set",
			input:   `{"credentialRefs":[{"name":"foo","nameField":"spec.name"}]}`,
			wantErr: "name and nameField are mutually exclusive",
		},
		{
			name:    "neither name nor nameField set",
			input:   `{"credentialRefs":[{"kind":"Secret"}]}`,
			wantErr: "one of name or nameField is required",
		},
		{
			name:    "both kind and kindField set",
			input:   `{"credentialRefs":[{"kind":"Secret","kindField":"spec.kind","nameField":"spec.name"}]}`,
			wantErr: "kind and kindField are mutually exclusive",
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

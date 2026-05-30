// Package credentialpolicy implements a validating webhook that ensures users
// have GET access to Secrets referenced by CAPI infrastructure resources.
package credentialpolicy

import (
	"encoding/json"
	"fmt"
)

const (
	// AnnotationKey is the annotation key placed on CRDs to describe credential references.
	AnnotationKey = "turtles-capi.cattle.io/sensitive-info"

	// ConfigMapName is the name of the ConfigMap containing credential policy configuration.
	ConfigMapName = "turtles-capi-credential-policy"

	// ConfigMapNamespace is the namespace where the credential policy ConfigMap resides.
	ConfigMapNamespace = "cattle-turtles-system"

	// MaxTraversalDepth is the safety limit for credential reference chain traversal.
	MaxTraversalDepth = 10
)

// CredentialPolicy defines how a CAPI resource references sensitive credentials.
// This schema is used in both the ConfigMap data values and CRD annotations.
type CredentialPolicy struct {
	CredentialRefs []CredentialRef `json:"credentialRefs"`
}

// CredentialRef describes a reference to either an identity object or a Secret.
// For each coordinate (apiVersion, kind, namespace, name), supply either the literal
// value OR the Field variant pointing to a dot-path in the object - never both.
//
// If the resolved kind equals "Secret", this is a terminal reference and
// a SubjectAccessReview for GET will be performed.
// Otherwise, the referenced object is treated as an intermediate identity
// and the traversal continues using that object's configuration.
type CredentialRef struct {
	// APIVersion is a literal apiVersion value (e.g. "infrastructure.cluster.x-k8s.io/v1beta2").
	APIVersion string `json:"apiVersion,omitempty"`
	// APIVersionField is a dot-path to extract the apiVersion from the object (e.g. "spec.identityRef.apiVersion").
	APIVersionField string `json:"apiVersionField,omitempty"`

	// Kind is a literal kind value (e.g. "Secret").
	Kind string `json:"kind,omitempty"`
	// KindField is a dot-path to extract the kind from the object (e.g. "spec.identityRef.kind").
	KindField string `json:"kindField,omitempty"`

	// Namespace is a literal namespace value (e.g. "capa-system").
	Namespace string `json:"namespace,omitempty"`
	// NamespaceField is a dot-path to extract the namespace from the object (e.g. "spec.identityRef.namespace").
	NamespaceField string `json:"namespaceField,omitempty"`

	// Name is a literal name value.
	Name string `json:"name,omitempty"`
	// NameField is a dot-path to extract the name from the object (e.g. "spec.identityRef.name").
	NameField string `json:"nameField,omitempty"`
}

// Validate checks that the CredentialPolicy is well-formed.
// Rules:
//   - For each coordinate, only the literal or the Field variant may be set, not both.
//   - Each CredentialRef must have at least a name or nameField.
func (p *CredentialPolicy) Validate() error {
	for i, ref := range p.CredentialRefs {
		if ref.APIVersion != "" && ref.APIVersionField != "" {
			return fmt.Errorf("credentialRefs[%d]: apiVersion and apiVersionField are mutually exclusive", i)
		}
		if ref.Kind != "" && ref.KindField != "" {
			return fmt.Errorf("credentialRefs[%d]: kind and kindField are mutually exclusive", i)
		}
		if ref.Namespace != "" && ref.NamespaceField != "" {
			return fmt.Errorf("credentialRefs[%d]: namespace and namespaceField are mutually exclusive", i)
		}
		if ref.Name != "" && ref.NameField != "" {
			return fmt.Errorf("credentialRefs[%d]: name and nameField are mutually exclusive", i)
		}
		if ref.Name == "" && ref.NameField == "" {
			return fmt.Errorf("credentialRefs[%d]: one of name or nameField is required", i)
		}
	}
	return nil
}

// ParseCredentialPolicy deserializes and validates a CredentialPolicy from JSON.
func ParseCredentialPolicy(data string) (*CredentialPolicy, error) {
	if data == "" {
		return nil, nil
	}
	var policy CredentialPolicy
	if err := json.Unmarshal([]byte(data), &policy); err != nil {
		return nil, fmt.Errorf("failed to parse credential policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

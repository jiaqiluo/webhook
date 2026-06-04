// Package credentialpolicy implements a validating webhook that ensures users
// have GET access to Secrets referenced by CAPI infrastructure resources.
package credentialpolicy

import (
	"encoding/json"
	"fmt"
)

const (
	// AnnotationKey is the annotation key placed on CRDs to describe credential references.
	AnnotationKey = "turtles-capi.cattle.io/credential-policy"

	// LabelKey is the label key used to identify ConfigMaps that contain credential policies.
	// Turtles places this label on the per-provider "credential-policies" ConfigMap.
	LabelKey = "turtles-capi.cattle.io/credential-policy"

	// LabelValue is the value of the credential policy label.
	LabelValue = "true"

	// ConfigMapName is the conventional name of the per-provider credential policy ConfigMap.
	// Each provider hosts one ConfigMap with this name in its own namespace
	// (e.g. capa-system/credential-policies, capv-system/credential-policies).
	ConfigMapName = "credential-policies"

	// MaxTraversalDepth is the safety limit for credential reference chain traversal.
	MaxTraversalDepth = 10
)

// CredentialPolicy defines how a CAPI resource references sensitive credentials.
// This schema is used in both the ConfigMap data values and CRD annotations.
type CredentialPolicy struct {
	CredentialRef CredentialRef `json:"credentialRef"`
}

// CredentialRef describes a reference to either an identity object or a Secret.
//
// Each coordinate field (APIVersion, Kind, Namespace, Name) supports three formats
// determined by the value's prefix:
//
//   - "."  prefix — dot-path into the admitted object (e.g. ".spec.identityRef.kind").
//     The leading dot is stripped and the remainder is split on "." for traversal.
//   - "$"  prefix — JSONPath expression (e.g. "$.spec.containers[0].name").
//   - no prefix — literal value (e.g. "Secret", "capa-system").
//
// If the resolved kind equals "Secret", this is a terminal reference and
// a SubjectAccessReview for GET will be performed.
// Otherwise, the referenced object is treated as an intermediate identity
// and the traversal continues using that object's configuration.
type CredentialRef struct {
	// APIVersion is the apiVersion coordinate.
	// Use a literal (e.g. "infrastructure.cluster.x-k8s.io/v1beta2") or
	// a dot-path (e.g. ".spec.identityRef.apiVersion"), or
	// a JSONPath (e.g. "$.spec.identityRef.apiVersion").
	// Defaults to the source resource's group/version if empty or unresolved.
	APIVersion string `json:"apiVersion,omitempty"`

	// Kind is the kind coordinate.
	// Use a literal (e.g. "Secret") or a dot-path (e.g. ".spec.identityRef.kind"), or
	// a JSONPath (e.g. "$.spec.identityRef.kind").
	Kind string `json:"kind,omitempty"`

	// Namespace is the namespace coordinate.
	// Use a literal (e.g. "capa-system") or a dot-path (e.g. ".spec.identityRef.namespace"), or
	// a JSONPath (e.g. "$.spec.identityRef.namespace").
	Namespace string `json:"namespace,omitempty"`

	// Name is the name coordinate. Required (must resolve to a non-empty value or the
	// reference is treated as optional/unset and the check is skipped).
	// Use a literal or a dot-path (e.g. ".spec.identityRef.name"), or
	// a JSONPath (e.g. "$.spec.identityRef.name").
	Name string `json:"name,omitempty"`
}

// Validate checks that the CredentialPolicy is well-formed.
// The CredentialRef must have a non-empty Name.
func (p *CredentialPolicy) Validate() error {
	if p.CredentialRef.Name == "" {
		return fmt.Errorf("credentialRef: name is required")
	}
	return nil
}

// ParseCredentialPolicy deserializes and validates a CredentialPolicy from JSON.
// Returns nil if data is empty (no policy configured).
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

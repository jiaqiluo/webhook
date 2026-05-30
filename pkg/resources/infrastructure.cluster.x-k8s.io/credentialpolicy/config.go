package credentialpolicy

import (
	"sync"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ConfigStore holds the parsed credential policy configuration from both the
// ConfigMap and CRD annotations. It is safe for concurrent use.
//
// Merge order: ConfigMap entry > CRD annotation > nil (no config).
type ConfigStore struct {
	mu                sync.RWMutex
	configMapPolicies map[string]*CredentialPolicy // key: "group/version/resource"
	crdPolicies       map[string]*CredentialPolicy // key: "group/version/resource"
}

// NewConfigStore creates an initialized ConfigStore.
func NewConfigStore() *ConfigStore {
	return &ConfigStore{
		configMapPolicies: make(map[string]*CredentialPolicy),
		crdPolicies:       make(map[string]*CredentialPolicy),
	}
}

// gvrKey returns the canonical key for a GVR: "group/version/resource".
func gvrKey(gvr schema.GroupVersionResource) string {
	return gvr.Group + "/" + gvr.Version + "/" + gvr.Resource
}

// GetPolicy returns the effective policy for the given GVR.
// Returns nil if no configuration exists (meaning no check is needed).
func (s *ConfigStore) GetPolicy(gvr schema.GroupVersionResource) *CredentialPolicy {
	key := gvrKey(gvr)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if p, ok := s.configMapPolicies[key]; ok {
		return p
	}
	if p, ok := s.crdPolicies[key]; ok {
		return p
	}
	return nil
}

// UpdateConfigMap replaces all ConfigMap-sourced policies.
// Entries that fail to parse are logged and skipped.
func (s *ConfigStore) UpdateConfigMap(data map[string]string) {
	parsed := make(map[string]*CredentialPolicy, len(data))
	for key, raw := range data {
		policy, err := ParseCredentialPolicy(raw)
		if err != nil {
			logrus.Errorf("credential-policy configmap: invalid entry %q: %v", key, err)
			continue
		}
		if policy != nil {
			parsed[key] = policy
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.configMapPolicies = parsed
}

// UpdateCRDAnnotation updates or removes the policy derived from a single CRD's annotation.
func (s *ConfigStore) UpdateCRDAnnotation(gvr schema.GroupVersionResource, raw string) {
	key := gvrKey(gvr)

	if raw == "" {
		s.mu.Lock()
		delete(s.crdPolicies, key)
		s.mu.Unlock()
		return
	}

	policy, err := ParseCredentialPolicy(raw)
	if err != nil {
		logrus.Errorf("credential-policy CRD annotation for %s: %v", key, err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if policy != nil {
		s.crdPolicies[key] = policy
	} else {
		delete(s.crdPolicies, key)
	}
}

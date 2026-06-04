package credentialpolicy

import (
	"sync"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ConfigStore holds the parsed credential policy configuration derived from
// CRD annotations. It is safe for concurrent use.
type ConfigStore struct {
	mu sync.RWMutex
	// crdPolicies: key = gvrKey
	crdPolicies map[string]*CredentialPolicy
	// crdNameToGVR maps the CRD metadata.name (e.g.
	// "awsclusters.infrastructure.cluster.x-k8s.io") to the gvrKey it
	// contributed, enabling clean removal when a CRD is deleted.
	crdNameToGVR map[string]string
}

// NewConfigStore creates an initialized ConfigStore.
func NewConfigStore() *ConfigStore {
	return &ConfigStore{
		crdPolicies:  make(map[string]*CredentialPolicy),
		crdNameToGVR: make(map[string]string),
	}
}

// gvrKey returns the canonical lookup key for a GVR: "group/version/resource".
func gvrKey(gvr schema.GroupVersionResource) string {
	return gvr.Group + "/" + gvr.Version + "/" + gvr.Resource
}

// GetPolicy returns the effective policy for the given GVR.
// Returns nil if no configuration exists (resource is unconfigured — allow through).
func (s *ConfigStore) GetPolicy(gvr schema.GroupVersionResource) *CredentialPolicy {
	key := gvrKey(gvr)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.crdPolicies[key]
}

// UpdateCRDAnnotation updates or removes the policy derived from a CRD's
// annotation. crdName is the CRD's metadata.name (e.g.
// "awsclusters.infrastructure.cluster.x-k8s.io") and is stored for later
// clean removal via DeleteCRDAnnotation.
func (s *ConfigStore) UpdateCRDAnnotation(crdName string, gvr schema.GroupVersionResource, raw string) {
	key := gvrKey(gvr)

	if raw == "" {
		s.mu.Lock()
		delete(s.crdPolicies, key)
		delete(s.crdNameToGVR, crdName)
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
		s.crdNameToGVR[crdName] = key
	} else {
		delete(s.crdPolicies, key)
		delete(s.crdNameToGVR, crdName)
	}
}

// DeleteCRDAnnotation removes the policy contributed by the named CRD.
// crdName is the CRD's metadata.name (e.g.
// "awsclusters.infrastructure.cluster.x-k8s.io").
func (s *ConfigStore) DeleteCRDAnnotation(crdName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.crdNameToGVR[crdName]; ok {
		delete(s.crdPolicies, key)
		delete(s.crdNameToGVR, crdName)
	}
}

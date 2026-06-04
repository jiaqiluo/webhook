package credentialpolicy

import (
	"context"
	"sync"

	"github.com/rancher/webhook/pkg/clients"
	"github.com/sirupsen/logrus"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ConfigStore holds the parsed credential policy configuration from both the
// per-provider ConfigMaps and CRD annotations. It is safe for concurrent use.
//
// Merge order: ConfigMap entry > CRD annotation > nil (no config).
//
// Multiple ConfigMaps (one per provider namespace) are tracked independently
// so that updating or deleting one ConfigMap only affects its own entries.
// If two ConfigMaps define a policy for the same GVR, the one with the
// alphabetically earlier "namespace/name" key wins; a warning is logged at
// write time (not on every read).
type ConfigStore struct {
	mu sync.RWMutex
	// configMapPolicies: outer key = "namespace/name", inner key = gvrKey
	configMapPolicies map[string]map[string]*CredentialPolicy
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
		configMapPolicies: make(map[string]map[string]*CredentialPolicy),
		crdPolicies:       make(map[string]*CredentialPolicy),
		crdNameToGVR:      make(map[string]string),
	}
}

// SetupCredentialPolicyStore initializes a ConfigStore with existing CRD annotations,
// and sets up watchers to keep it updated on future CRD changes.
// It returns the initialized store.
func SetupCredentialPolicyStore(clients *clients.Clients) *ConfigStore {
	// CAPI credential policy validator — seeded from CRD annotations.
	store := NewConfigStore()

	// Seed from all existing infrastructure.cluster.x-k8s.io CRDs.
	existingCRDs, crdListErr := clients.CRD.CustomResourceDefinition().Cache().List(labels.Everything())
	if crdListErr != nil {
		logrus.Warnf("credential-policy: failed to list CRDs: %v", crdListErr)
	} else {
		for _, crd := range existingCRDs {
			OnCRDChange(store, crd)
		}
	}

	// Watch for future CRD additions, updates, and deletions.
	clients.CRD.CustomResourceDefinition().OnChange(context.Background(), "credential-policy-crd-watcher",
		func(key string, crd *apiextensionsv1.CustomResourceDefinition) (*apiextensionsv1.CustomResourceDefinition, error) {
			if crd == nil || crd.DeletionTimestamp != nil {
				OnCRDDelete(store, key)
			} else {
				OnCRDChange(store, crd)
			}
			return nil, nil
		})
	return store
}

// gvrKey returns the canonical lookup key for a GVR: "group/version/resource".
func gvrKey(gvr schema.GroupVersionResource) string {
	return gvr.Group + "/" + gvr.Version + "/" + gvr.Resource
}

// cmKey returns the lookup key for a ConfigMap: "namespace/name".
func cmKey(namespace, name string) string {
	return namespace + "/" + name
}

// GetPolicy returns the effective policy for the given GVR.
// Returns nil if no configuration exists (resource is unconfigured — allow through).
func (s *ConfigStore) GetPolicy(gvr schema.GroupVersionResource) *CredentialPolicy {
	key := gvrKey(gvr)
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Pick the ConfigMap with the alphabetically earliest "namespace/name" key.
	var winner *CredentialPolicy
	var winnerCMKey string

	for cmk, policies := range s.configMapPolicies {
		if p, ok := policies[key]; ok {
			if winner == nil || cmk < winnerCMKey {
				winner = p
				winnerCMKey = cmk
			}
		}
	}
	if winner != nil {
		return winner
	}

	return s.crdPolicies[key]
}

// UpdateFromConfigMap replaces the policy entries contributed by a single
// ConfigMap. Entries that fail to parse are logged and skipped.
// A warning is logged at write time if the incoming data introduces a GVR
// that is already defined by another ConfigMap.
func (s *ConfigStore) UpdateFromConfigMap(namespace, name string, data map[string]string) {
	key := cmKey(namespace, name)
	parsed := make(map[string]*CredentialPolicy, len(data))

	for gvr, raw := range data {
		policy, err := ParseCredentialPolicy(raw)
		if err != nil {
			logrus.Errorf("credential-policy configmap %s: invalid entry %q: %v", key, gvr, err)
			continue
		}
		if policy != nil {
			parsed[gvr] = policy
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Warn about GVR conflicts at write time (not on every read).
	for gvr := range parsed {
		for otherKey, otherPolicies := range s.configMapPolicies {
			if otherKey == key {
				continue
			}
			if _, exists := otherPolicies[gvr]; exists {
				logrus.Warnf("credential-policy: GVR %q defined in both ConfigMap %q and %q", gvr, key, otherKey)
			}
		}
	}

	s.configMapPolicies[key] = parsed
}

// DeleteConfigMap removes all policy entries contributed by the named ConfigMap.
func (s *ConfigStore) DeleteConfigMap(namespace, name string) {
	key := cmKey(namespace, name)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.configMapPolicies, key)
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

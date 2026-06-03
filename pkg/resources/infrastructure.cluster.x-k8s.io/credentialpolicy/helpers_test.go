package credentialpolicy

import "sort"

// configMapKeys returns a sorted list of all tracked ConfigMap keys.
// Test-only helper; not part of the public API.
func (s *ConfigStore) configMapKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.configMapPolicies))
	for k := range s.configMapPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

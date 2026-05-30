package credentialpolicy

import (
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// RefreshConfigMapData updates the ConfigStore with new ConfigMap data.
// This function is designed to be called from a ConfigMap informer event handler.
func RefreshConfigMapData(store *ConfigStore, cm *corev1.ConfigMap) {
	if cm == nil {
		store.UpdateConfigMap(nil)
		return
	}
	logrus.Infof("credential-policy: refreshing config from ConfigMap %s/%s", cm.Namespace, cm.Name)
	store.UpdateConfigMap(cm.Data)
}

// ProcessCRDAnnotation extracts the credential policy annotation from a CRD
// object and updates the ConfigStore. The CRD is expected to be an unstructured
// representation of an apiextensions/v1 CustomResourceDefinition.
//
// This function is designed to be called from a CRD informer event handler.
func ProcessCRDAnnotation(store *ConfigStore, obj *unstructured.Unstructured) {
	if obj == nil {
		return
	}

	annotations := obj.GetAnnotations()
	raw := annotations[AnnotationKey]

	// Extract GVR from the CRD spec
	group, _, _ := unstructured.NestedString(obj.Object, "spec", "group")
	// Only process CRDs in the infrastructure.cluster.x-k8s.io group
	if group != "infrastructure.cluster.x-k8s.io" {
		return
	}

	version := extractServingVersion(obj)
	if version == "" {
		return
	}

	resourcePlural, _, _ := unstructured.NestedString(obj.Object, "spec", "names", "plural")
	if resourcePlural == "" {
		return
	}

	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resourcePlural,
	}

	store.UpdateCRDAnnotation(gvr, raw)
}

// extractServingVersion returns the served+storage version from a CRD, or the
// first served version if no storage version is found.
func extractServingVersion(obj *unstructured.Unstructured) string {
	versions, found, err := unstructured.NestedSlice(obj.Object, "spec", "versions")
	if err != nil || !found || len(versions) == 0 {
		return ""
	}

	var firstServed string
	for _, v := range versions {
		vMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		name, _, _ := unstructured.NestedString(vMap, "name")
		served, _, _ := unstructured.NestedBool(vMap, "served")
		storage, _, _ := unstructured.NestedBool(vMap, "storage")

		if served && storage {
			return name
		}
		if served && firstServed == "" {
			firstServed = name
		}
	}
	return firstServed
}

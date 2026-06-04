package credentialpolicy

import (
	"github.com/sirupsen/logrus"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// OnCRDChange updates the ConfigStore when a CustomResourceDefinition is added or updated.
// Only CRDs in the "infrastructure.cluster.x-k8s.io" API group are processed;
// the AnnotationKey annotation value (empty string if absent) is
// used to set or clear the policy for this resource type.
func OnCRDChange(store *ConfigStore, crd *apiextensionsv1.CustomResourceDefinition) {
	if crd == nil || crd.DeletionTimestamp != nil {
		return
	}
	if crd.Spec.Group != "infrastructure.cluster.x-k8s.io" {
		return
	}

	version := servingVersion(crd)
	if version == "" {
		logrus.Warnf("credential-policy: CRD %s has no served version; skipping", crd.Name)
		return
	}
	resource := crd.Spec.Names.Plural
	if resource == "" {
		logrus.Warnf("credential-policy: CRD %s has no plural name; skipping", crd.Name)
		return
	}

	gvr := schema.GroupVersionResource{
		Group:    crd.Spec.Group,
		Version:  version,
		Resource: resource,
	}

	raw := crd.Annotations[AnnotationKey]
	logrus.Debugf("credential-policy: processing CRD annotation for %s/%s/%s (present=%v)",
		gvr.Group, gvr.Version, gvr.Resource, raw != "")
	store.UpdateCRDAnnotation(crd.Name, gvr, raw)
}

// OnCRDDelete removes ConfigStore entries contributed by a deleted CRD.
// crdName is the value of the CRD's metadata.name field, which the Wrangler
// OnChange handler passes as the key when the object is nil.
func OnCRDDelete(store *ConfigStore, crdName string) {
	logrus.Debugf("credential-policy: removing CRD annotation for deleted CRD %s", crdName)
	store.DeleteCRDAnnotation(crdName)
}

// servingVersion returns the name of the served+storage version of the CRD.
// If no single version is both served and storage (unusual), it returns the
// first served version; empty string if none are served.
func servingVersion(crd *apiextensionsv1.CustomResourceDefinition) string {
	var firstServed string
	for _, v := range crd.Spec.Versions {
		if v.Served && v.Storage {
			return v.Name
		}
		if v.Served && firstServed == "" {
			firstServed = v.Name
		}
	}
	return firstServed
}

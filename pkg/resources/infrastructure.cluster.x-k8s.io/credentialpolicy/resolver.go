package credentialpolicy

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// resolveField returns the literal value if non-empty, otherwise extracts
// the value at the given dot-path from the unstructured object.
// Returns empty string if the path does not exist or the value is not a string.
func resolveField(literal, fieldPath string, obj *unstructured.Unstructured) string {
	if literal != "" {
		return literal
	}
	if fieldPath == "" || obj == nil {
		return ""
	}

	parts := strings.Split(fieldPath, ".")
	val, found, err := unstructured.NestedString(obj.Object, parts...)
	if err != nil || !found {
		return ""
	}
	return val
}

// resolvedRef holds the resolved coordinates of a credential reference.
type resolvedRef struct {
	apiVersion string
	kind       string
	namespace  string
	name       string
}

// resolveCredentialRef resolves a CredentialRef against an unstructured object,
// using the given GVR as the default apiVersion source.
func resolveCredentialRef(ref CredentialRef, obj *unstructured.Unstructured, sourceGVR schema.GroupVersionResource) resolvedRef {
	resolved := resolvedRef{
		apiVersion: resolveField(ref.APIVersion, ref.APIVersionField, obj),
		kind:       resolveField(ref.Kind, ref.KindField, obj),
		namespace:  resolveField(ref.Namespace, ref.NamespaceField, obj),
		name:       resolveField(ref.Name, ref.NameField, obj),
	}

	// Default apiVersion to the source resource's group/version
	if resolved.apiVersion == "" {
		resolved.apiVersion = sourceGVR.Group + "/" + sourceGVR.Version
	}

	return resolved
}

// visitedKey is used for loop detection during chain traversal.
type visitedKey struct {
	apiVersion string
	kind       string
	namespace  string
	name       string
}

// chainResult represents the outcome of traversing a credential reference chain.
type chainResult struct {
	// secretName is the name of the terminal Secret (empty if no check needed).
	secretName string
	// secretNamespace is the namespace of the terminal Secret.
	secretNamespace string
	// err is set if traversal failed (identity not found, loop, depth exceeded).
	err error
	// skip is true if the chain resolved to empty (optional ref, no credential).
	skip bool
}

// objectGetter is an interface for fetching objects from cache by GVK.
type objectGetter interface {
	Get(gvk schema.GroupVersionKind, namespace, name string) (*unstructured.Unstructured, error)
}

// dynamicController is the interface we need from lasso's dynamic.Controller.
type dynamicController interface {
	Get(gvk schema.GroupVersionKind, namespace, name string) (k8sruntime.Object, error)
}

// DynamicObjectGetter adapts lasso's dynamic.Controller to the objectGetter interface.
type DynamicObjectGetter struct {
	Dynamic dynamicController
}

// Get fetches an object by GVK from the lasso dynamic controller cache and
// returns it as an *unstructured.Unstructured.
func (d *DynamicObjectGetter) Get(gvk schema.GroupVersionKind, namespace, name string) (*unstructured.Unstructured, error) {
	obj, err := d.Dynamic.Get(gvk, namespace, name)
	if err != nil {
		return nil, err
	}

	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u, nil
	}

	// Convert typed object to unstructured
	data, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert object to unstructured: %w", err)
	}
	return &unstructured.Unstructured{Object: data}, nil
}

// TraverseCredentialChain follows the credential reference chain starting from
// the given object and its config, returning the terminal Secret coordinates
// or an error if traversal fails.
//
// Parameters:
//   - obj: the admitted resource as unstructured
//   - sourceGVR: the GVR of the admitted resource
//   - policy: the credential policy for this resource type
//   - store: config store for looking up intermediate policies
//   - getter: cached object getter for fetching intermediate identity objects
//   - objectNamespace: the namespace of the admitted object (from the request)
func TraverseCredentialChain(
	obj *unstructured.Unstructured,
	sourceGVR schema.GroupVersionResource,
	policy *CredentialPolicy,
	store *ConfigStore,
	getter objectGetter,
	objectNamespace string,
) chainResult {
	if policy == nil || len(policy.CredentialRefs) == 0 {
		return chainResult{skip: true}
	}

	visited := make(map[visitedKey]bool)
	currentObj := obj
	currentGVR := sourceGVR
	currentPolicy := policy
	currentNamespace := objectNamespace

	for depth := 0; depth < MaxTraversalDepth; depth++ {
		ref := currentPolicy.CredentialRefs[0]
		resolved := resolveCredentialRef(ref, currentObj, currentGVR)

		// If name is empty, the reference is optional/unset - skip
		if resolved.name == "" {
			return chainResult{skip: true}
		}

		// Terminal: resolved kind is Secret
		if resolved.kind == "Secret" {
			secretNs := resolved.namespace
			if secretNs == "" {
				secretNs = currentNamespace
			}
			if secretNs == "" {
				return chainResult{err: fmt.Errorf("cannot determine namespace for Secret %q: no namespace in config and resource is cluster-scoped", resolved.name)}
			}
			return chainResult{secretName: resolved.name, secretNamespace: secretNs}
		}

		// Non-terminal: intermediate identity object
		// Loop detection
		key := visitedKey{
			apiVersion: resolved.apiVersion,
			kind:       resolved.kind,
			namespace:  resolved.namespace,
			name:       resolved.name,
		}
		if visited[key] {
			return chainResult{err: fmt.Errorf("circular credential reference detected at %s/%s %s/%s", resolved.apiVersion, resolved.kind, resolved.namespace, resolved.name)}
		}
		visited[key] = true

		// Parse apiVersion to get GVK
		gv, err := schema.ParseGroupVersion(resolved.apiVersion)
		if err != nil {
			return chainResult{err: fmt.Errorf("invalid apiVersion %q: %w", resolved.apiVersion, err)}
		}
		gvk := gv.WithKind(resolved.kind)

		// Fetch the intermediate object from cache
		identityObj, err := getter.Get(gvk, resolved.namespace, resolved.name)
		if err != nil {
			return chainResult{err: fmt.Errorf("referenced identity object %s %s/%s not found: %w", gvk.String(), resolved.namespace, resolved.name, err)}
		}

		// Look up the config for the identity object's type
		identityGVR := gvrFromGVK(gvk)
		identityPolicy := store.GetPolicy(identityGVR)
		if identityPolicy == nil || len(identityPolicy.CredentialRefs) == 0 {
			// Identity has no credential chain configured - skip
			return chainResult{skip: true}
		}

		// Continue traversal with the identity object
		currentObj = identityObj
		currentGVR = identityGVR
		currentPolicy = identityPolicy
		currentNamespace = identityObj.GetNamespace()
	}

	return chainResult{err: fmt.Errorf("credential reference chain exceeded maximum depth of %d", MaxTraversalDepth)}
}

// gvrFromGVK derives the GVR from a GVK using simple pluralization.
// This works for all known CAPI identity types:
//
//	AWSClusterStaticIdentity -> awsclusterstaticidentities
//	AWSClusterRoleIdentity -> awsclusterroleidentities
//	VSphereClusterIdentity -> vsphereclusteridentities
//	AzureClusterIdentity -> azureclusteridentities
func gvrFromGVK(gvk schema.GroupVersionKind) schema.GroupVersionResource {
	resource := strings.ToLower(gvk.Kind)
	if strings.HasSuffix(resource, "y") {
		resource = resource[:len(resource)-1] + "ies"
	} else if !strings.HasSuffix(resource, "s") {
		resource = resource + "s"
	}
	return schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: resource,
	}
}

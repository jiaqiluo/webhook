package credentialpolicy

import (
	"bytes"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/jsonpath"
)

const (
	rancherCredentialsNamespace = "cattle-global-data"
	providerNamespaceCAPA       = "capa-system"
)

// resolveValue resolves a single coordinate value against an unstructured object.
// The value's prefix determines interpretation:
//
//   - "." prefix — dot-path into the object (e.g. ".spec.identityRef.kind").
//     The leading dot is stripped and the remainder split on "." for traversal.
//   - "$" prefix — JSONPath expression (e.g. "$.spec.containers[0].name").
//   - no prefix — literal string returned as-is.
//
// Returns the resolved string and any error (only possible for "$" prefix today).
func resolveValue(value string, obj *unstructured.Unstructured) (string, error) {
	if value == "" {
		return "", nil
	}

	switch {
	case strings.HasPrefix(value, "."):
		if obj == nil {
			return "", nil
		}
		parts := strings.Split(strings.TrimPrefix(value, "."), ".")
		val, found, err := unstructured.NestedString(obj.Object, parts...)
		if err != nil || !found {
			return "", nil
		}
		return val, nil

	case strings.HasPrefix(value, "$"):
		if obj == nil {
			return "", nil
		}
		return evaluateJSONPath(value, obj.Object)

	default:
		return value, nil
	}
}

// evaluateJSONPath evaluates a JSONPath expression (with "$" prefix, e.g.
// "$.spec.containers[0].name") against the given data map and returns the
// result as a string. The expression is wrapped in "{}" as required by the
// k8s.io/client-go/util/jsonpath library.
//
// Missing keys are treated as empty string (not an error), so optional
// credential references behave consistently with dot-path resolution.
// A parse error (malformed expression) is returned as a hard error.
func evaluateJSONPath(expr string, data map[string]interface{}) (string, error) {
	jp := jsonpath.New("credentialpolicy").AllowMissingKeys(true)

	// Wrap the raw expression in "{}" as expected by the library.
	// e.g. "$.spec.foo" → "{$.spec.foo}"
	if err := jp.Parse("{" + expr + "}"); err != nil {
		return "", fmt.Errorf("failed to parse JSONPath expression %q: %w", expr, err)
	}

	var buf bytes.Buffer
	if err := jp.Execute(&buf, data); err != nil {
		// With AllowMissingKeys(true) this should only trigger on structural errors.
		return "", fmt.Errorf("failed to evaluate JSONPath expression %q: %w", expr, err)
	}

	return buf.String(), nil
}

type resolvedRef struct {
	apiVersion string
	kind       string
	namespace  string
	name       string
}

// resolveCredentialRef resolves a CredentialRef against an unstructured object,
// using the given GVR as the default apiVersion source.
// Returns an error if any field value uses an unsupported format (e.g. "$" prefix).
func resolveCredentialRef(ref CredentialRef, obj *unstructured.Unstructured, sourceGVR schema.GroupVersionResource) (resolvedRef, error) {
	apiVersion, err := resolveValue(ref.APIVersion, obj)
	if err != nil {
		return resolvedRef{}, fmt.Errorf("apiVersion: %w", err)
	}
	kind, err := resolveValue(ref.Kind, obj)
	if err != nil {
		return resolvedRef{}, fmt.Errorf("kind: %w", err)
	}
	namespace, err := resolveValue(ref.Namespace, obj)
	if err != nil {
		return resolvedRef{}, fmt.Errorf("namespace: %w", err)
	}
	name, err := resolveValue(ref.Name, obj)
	if err != nil {
		return resolvedRef{}, fmt.Errorf("name: %w", err)
	}

	resolved := resolvedRef{
		apiVersion: apiVersion,
		kind:       kind,
		namespace:  namespace,
		name:       name,
	}

	// Default apiVersion to the source resource's group/version
	if resolved.apiVersion == "" {
		resolved.apiVersion = sourceGVR.Group + "/" + sourceGVR.Version
	}

	if resolved.kind == "Secret" {
		resolved.apiVersion = "v1"
	}

	return resolved, nil
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

// traverseCredentialChain follows the credential reference chain starting from
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
func traverseCredentialChain(obj *unstructured.Unstructured, sourceGVR schema.GroupVersionResource,
	policy *CredentialPolicy, store *ConfigStore, getter objectGetter, objectNamespace string) chainResult {
	if policy == nil {
		return chainResult{skip: true}
	}

	visited := make(map[visitedKey]bool)
	currentObj := obj
	currentGVR := sourceGVR
	currentPolicy := policy
	currentNamespace := objectNamespace

	for depth := 0; depth < MaxTraversalDepth; depth++ {
		ref := currentPolicy.CredentialRef
		resolved, err := resolveCredentialRef(ref, currentObj, currentGVR)
		if err != nil {
			return chainResult{err: fmt.Errorf("failed to resolve credential ref: %w", err)}
		}

		if resolved.name == "" {
			return chainResult{skip: true}
		}

		// Terminal: resolved kind is Secret
		if strings.ToLower(resolved.kind) == "secret" {
			secretNs := resolved.namespace
			if secretNs == "" {
				secretNs = currentNamespace
			}
			if currentGVR.Resource == "awsclusterstaticidentities" && secretNs == providerNamespaceCAPA {
				// the secret is a mirror of rancher cloud credential managed by Turtles
				secretNs = rancherCredentialsNamespace
			}
			if secretNs == "" {
				return chainResult{err: fmt.Errorf("cannot determine namespace for Secret %q: no namespace in policy", resolved.name)}
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
			return chainResult{err: fmt.Errorf("circular credential reference detected at %s/%s %s/%s",
				resolved.apiVersion, resolved.kind, resolved.namespace, resolved.name)}
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
			return chainResult{err: fmt.Errorf("failed to get referenced identity object: %w", err)}
		}

		// Look up the config for the identity object's type
		identityGVR := gvrFromGVK(gvk)
		identityPolicy := store.GetPolicy(identityGVR)
		if identityPolicy == nil {
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

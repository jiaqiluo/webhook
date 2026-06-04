## Validation Checks

This package implements a validating webhook for resources in the `infrastructure.cluster.x-k8s.io` API group.

The webhook ensures that the requesting user has permission to `get` the Rancher Cloud Credential, a K8s Secret, referenced by the resource's credential chain.

### Scope and Operations

- Group/Version/Resource scope: `infrastructure.cluster.x-k8s.io/*/*`
- Operations: `CREATE`, `UPDATE`
- Resources with no configured credential policy are allowed.

### Policy Source

Credential policies are loaded from CRD annotations only.

- Annotation key: `turtles-capi.cattle.io/credential-policy`
- Policy schema: JSON with a single `credentialRef` object
- Reference fields (`apiVersion`, `kind`, `namespace`, `name`) support:
  - Dot-path values prefixed with `.`
  - JSONPath values prefixed with `$`
  - Literal values (no prefix)

Example:
```
turtles-capi.cattle.io/credential-policy='{"credentialRef":{"kind":"Secret","name":".spec.secretRef", "namespace":"capa-system"}}'
```

### Credential Chain Resolution

The webhook resolves the configured `credentialRef` from the admitted object.

- If resolved `kind` is `Secret`, this is the terminal reference.
- Otherwise, it fetches the referenced identity object and continues traversal using that object's own policy.
- Traversal protections:
  - Circular reference detection
  - Maximum depth limit (`MaxTraversalDepth`)
- If the resolved reference name is empty, the reference is treated as optional and the request is allowed.

### UPDATE Optimization

On `UPDATE`, if the resolved credential reference did not change between old and new objects, the request is allowed without performing SubjectAccessReview.

### Access Enforcement

For a terminal Secret reference, the webhook performs SubjectAccessReview:

- Verb: `get`
- Resource: `core/v1/secrets`
- Name/namespace: resolved from the credential chain

If access is denied, the request is rejected with a `403 Forbidden` response.

### Special Namespace Handling

For CAPA static identities, when the resolved secret namespace is `capa-system`, the webhook checks access in `cattle-global-data` 
because the Secret is expected to be mirrored there by Turtles. 

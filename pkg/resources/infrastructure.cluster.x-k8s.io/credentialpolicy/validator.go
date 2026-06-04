package credentialpolicy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

var webhookGVR = schema.GroupVersionResource{
	Group:    "infrastructure.cluster.x-k8s.io",
	Version:  "*",
	Resource: "*",
}

var secretGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}

// Validator implements admission.ValidatingAdmissionHandler for CAPI infrastructure
// credential policy enforcement.
type Validator struct {
	admitter admitter
}

// NewValidator creates a new credential policy validator.
func NewValidator(store *ConfigStore, getter objectGetter, sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		admitter: admitter{
			store:  store,
			getter: getter,
			sar:    sar,
		},
	}
}

// GVR returns the GroupVersionResource for this webhook.
func (v *Validator) GVR() schema.GroupVersionResource {
	return webhookGVR
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.AllScopes, v.Operations()),
	}
}

// Admitters returns the admitter objects used to validate credential references.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	store  *ConfigStore
	getter objectGetter
	sar    authorizationv1.SubjectAccessReviewInterface
}

// Admit handles the webhook admission request.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("credentialPolicyValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	// Determine the GVR of the incoming resource
	requestGVR := schema.GroupVersionResource{
		Group:    request.Resource.Group,
		Version:  request.Resource.Version,
		Resource: request.Resource.Resource,
	}

	// Look up configuration for this resource type
	policy := a.store.GetPolicy(requestGVR)
	if policy == nil {
		// No configuration for this resource type - allow
		logrus.Tracef("credentialPolicyValidator: no policy for %s, allowing by default", requestGVR.String())
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	// Parse the new object
	newObj, err := unmarshalUnstructured(request.Object.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal new object: %w", err)
	}

	// For UPDATE operations, check if the credential reference actually changed
	if request.Operation == admissionv1.Update {
		oldObj, err := unmarshalUnstructured(request.OldObject.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal old object: %w", err)
		}

		if !credentialRefChanged(policy, oldObj, newObj, requestGVR) {
			// Credential reference hasn't changed - allow without SAR
			logrus.Tracef("credentialPolicyValidator: credential reference unchanged for %s %s/%s, allowing without access review", requestGVR.String(), request.Namespace, request.Name)
			return &admissionv1.AdmissionResponse{Allowed: true}, nil
		}
	}

	// Traverse the credential reference chain
	result := traverseCredentialChain(newObj, requestGVR, policy, a.store, a.getter, request.Namespace)

	logrus.Tracef("credentialPolicyValidator: traversal result for %s %s/%s: skip=%v, secret=%s/%s, err=%v",
		requestGVR.String(), request.Namespace, request.Name, result.skip, result.secretNamespace, result.secretName, result.err)

	if result.skip {
		// Chain resolved to empty (optional ref not set) - allow
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	if result.err != nil {
		logrus.Warnf("credential-policy: traversal error for %s %s/%s by %s: %v",
			requestGVR.String(), request.Namespace, request.Name, request.UserInfo.Username, result.err)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("credential reference validation failed: %v", result.err),
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
			},
		}, nil
	}

	// Perform SubjectAccessReview for GET on the terminal Secret
	allowed, err := auth.RequestUserHasVerb(request, secretGVR, a.sar, "get", result.secretName, result.secretNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to perform access review for secret %s/%s: %w", result.secretNamespace, result.secretName, err)
	}

	if !allowed {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status: "Failure",
				Message: fmt.Sprintf("user %q does not have permission to get secret %s/%s referenced by this resource's credential chain",
					request.UserInfo.Username, result.secretNamespace, result.secretName),
				Reason: metav1.StatusReasonForbidden,
				Code:   http.StatusForbidden,
			},
		}, nil
	}

	return &admissionv1.AdmissionResponse{Allowed: true}, nil
}

// credentialRefChanged compares the resolved credential reference fields between
// old and new objects to determine if the reference actually changed.
// If resolution fails (e.g. unsupported prefix), conservatively returns true
// so the full validation is always run.
func credentialRefChanged(policy *CredentialPolicy, oldObj, newObj *unstructured.Unstructured, gvr schema.GroupVersionResource) bool {
	ref := policy.CredentialRef
	oldResolved, err := resolveCredentialRef(ref, oldObj, gvr)
	if err != nil {
		return true
	}
	newResolved, err := resolveCredentialRef(ref, newObj, gvr)
	if err != nil {
		return true
	}

	return oldResolved != newResolved
}

// unmarshalUnstructured decodes raw JSON into an Unstructured object.
func unmarshalUnstructured(raw []byte) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(raw, &obj.Object); err != nil {
		return nil, err
	}
	return obj, nil
}

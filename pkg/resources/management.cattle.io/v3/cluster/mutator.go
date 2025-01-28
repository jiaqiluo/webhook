package cluster

import (
	"encoding/json"
	"fmt"
	"reflect"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	psa "github.com/rancher/webhook/pkg/podsecurityadmission"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var managementGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusters",
}

func NewManagementClusterMutator(psactCache v3.PodSecurityAdmissionConfigurationTemplateCache, featureCache v3.FeatureCache) *ManagementClusterMutator {
	return &ManagementClusterMutator{
		psact:   psactCache,
		feature: featureCache,
	}
}

// ManagementClusterMutator implements admission.MutatingAdmissionWebhook.
type ManagementClusterMutator struct {
	psact   v3.PodSecurityAdmissionConfigurationTemplateCache
	feature v3.FeatureCache
}

// GVR returns the GroupVersionKind for this CRD.
func (m *ManagementClusterMutator) GVR() schema.GroupVersionResource {
	return managementGVR
}

// Operations returns list of operations handled by this mutator.
func (m *ManagementClusterMutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *ManagementClusterMutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.ClusterScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it is unable to process the request.
func (m *ManagementClusterMutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return admission.ResponseAllowed(), nil
	}
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new clusters from request: %w", err)
	}
	newClusterRaw, err := json.Marshal(newCluster)
	if err != nil {
		return nil, fmt.Errorf("unable to re-marshal new cluster: %w", err)
	}

	err = m.mutatePSACT(oldCluster, newCluster, request.Operation)
	if err != nil {
		return nil, fmt.Errorf("failed to mutate PSACT: %w", err)
	}
	err = m.mutateVersionManagement(newCluster, request.Operation)
	if err != nil {
		return nil, fmt.Errorf("failed to mutate VersionManagement: %w", err)
	}

	response := &admissionv1.AdmissionResponse{}
	// we use the re-marshalled new cluster to make sure that the patch doesn't drop "unknown" fields which were
	// in the json, but not in the cluster struct. This can occur due to out of date RKE versions
	if err := patch.CreatePatch(newClusterRaw, newCluster, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

// mutatePSACT updates the newCluster's Pod Security Admission (PSA) configuration based on changes to
// the cluster's `DefaultPodSecurityAdmissionConfigurationTemplateName`.
// It applies or removes the PSA plugin configuration depending on the operation and the current cluster state.
func (m *ManagementClusterMutator) mutatePSACT(oldCluster, newCluster *apisv3.Cluster, operation admissionv1.Operation) error {
	// no need to mutate the local cluster, or imported cluster which represents a KEv2 cluster (GKE/EKS/AKS) or v1 Provisioning Cluster
	if newCluster.Name == "local" || newCluster.Spec.RancherKubernetesEngineConfig == nil {
		return nil
	}
	if operation != admissionv1.Update && operation != admissionv1.Create {
		return nil
	}

	newTemplateName := newCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	oldTemplateName := oldCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName

	// If the template is set(or changed), update the cluster with the new template's content
	if newTemplateName != "" {
		err := m.setPSAConfig(newCluster)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to set PSAconfig: %w", err)
		}
		return nil
	}
	if operation == admissionv1.Update {
		// It is a valid use case where user switches from using PSACT to putting a PluginConfig for PSA under kube-api.AdmissionConfiguration,
		// but it is not a valid use case where the PluginConfig for PSA has the same content as the one in the previous-set PSACT,
		// so we need to drop it in this case.
		if oldTemplateName != "" {
			newConfig, found := psa.GetPluginConfigFromCluster(newCluster)
			if found {
				// found means there is a Plugin Config for PSA under the kube-api.admission_configuration section
				oldConfig, _ := psa.GetPluginConfigFromCluster(oldCluster)
				if reflect.DeepEqual(newConfig, oldConfig) {
					psa.DropPSAPluginConfigFromAdmissionConfig(newCluster)
					return nil
				}
			}
		}
	}
	return nil
}

// setPSAConfig makes sure that the PodSecurity config under the admission_configuration section matches the
// PodSecurityAdmissionConfigurationTemplate set in the cluster
func (m *ManagementClusterMutator) setPSAConfig(cluster *apisv3.Cluster) error {
	template, err := m.psact.Get(cluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName)
	if err != nil {
		return fmt.Errorf("failed to get PodSecurityAdmissionConfigurationTemplate: %w", err)
	}
	plugin, err := psa.GetPluginConfigFromTemplate(template, cluster.Spec.RancherKubernetesEngineConfig.Version)
	if err != nil {
		return fmt.Errorf("failed to get plugin config from template: %w", err)
	}
	admissionConfig := psa.GetAdmissionConfigFromCluster(cluster)
	found := false
	for i, item := range admissionConfig.Plugins {
		if item.Name == "PodSecurity" {
			admissionConfig.Plugins[i] = plugin
			found = true
			break
		}
	}
	if !found {
		admissionConfig.Plugins = append(admissionConfig.Plugins, plugin)
	}
	// now put the new admissionConfig back to the Cluster object
	cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration = admissionConfig
	return nil
}

// mutateVersionManagement sets or removes specific configuration fields (`Rke2Config` or `K3sConfig`)
// depending on whether the version management feature is enabled for the given cluster.
func (m *ManagementClusterMutator) mutateVersionManagement(new *apisv3.Cluster, operation admissionv1.Operation) error {
	if new.Status.Driver != apisv3.ClusterDriverRke2 && new.Status.Driver != apisv3.ClusterDriverK3s {
		return nil
	}
	if operation != admissionv1.Update && operation != admissionv1.Create {
		return nil
	}

	// determine whether the feature is enabled or not
	var enable bool
	switch new.Annotations[VersionManagementAnno] {
	case "true":
		enable = true
	case "false":
		enable = false
	case "system-default":
		f, err := m.feature.Get(VersionManagementFeature)
		if err != nil {
			return err
		}
		enable = isEnabled(f)
	default:
		f, err := m.feature.Get(VersionManagementFeature)
		if err != nil {
			return err
		}
		enable = isEnabled(f)
	}

	if enable {
		switch new.Status.Driver {
		case apisv3.ClusterDriverRke2:
			if new.Spec.Rke2Config == nil {
				// add the field only if it is missing
				new.Spec.Rke2Config = &apisv3.Rke2Config{}
				new.Spec.Rke2Config.SetStrategy(1, 1)
				if new.Status.Version != nil {
					new.Spec.Rke2Config.Version = new.Status.Version.String()
				}
				return nil
			}
		case apisv3.ClusterDriverK3s:
			if new.Spec.K3sConfig == nil {
				// add the field only if it is missing
				new.Spec.K3sConfig = &apisv3.K3sConfig{}
				new.Spec.K3sConfig.SetStrategy(1, 1)
				if new.Status.Version != nil {
					new.Spec.K3sConfig.Version = new.Status.Version.String()
				}
				return nil
			}
		}
	} else {
		switch new.Status.Driver {
		case apisv3.ClusterDriverRke2:
			new.Spec.Rke2Config = nil
			return nil
		case apisv3.ClusterDriverK3s:
			new.Spec.K3sConfig = nil
			return nil
		}
	}
	return nil
}

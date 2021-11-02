/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	SchemeBuilder.Register(&ManagedProxyConfiguration{}, &ManagedProxyConfigurationList{})
}

// ManagedProxyConfigurationSpec defines the desired state of ManagedProxyConfiguration
type ManagedProxyConfigurationSpec struct {
	// +required
	Authentication ManagedProxyConfigurationAuthentication `json:"authentication"`
	// +required
	ProxyServer ManagedProxyConfigurationProxyServer `json:"proxyServer"`
	// +required
	ProxyAgent ManagedProxyConfigurationProxyAgent `json:"proxyAgent"`
	// +optional
	Deploy *ManagedProxyConfigurationDeploy `json:"deploy,omitempty"`
}

// ManagedProxyConfigurationStatus defines the observed state of ManagedProxyConfiguration
type ManagedProxyConfigurationStatus struct {
	// +optional
	LastObservedGeneration int64 `json:"lastObservedGeneration,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// +genclient
// +genclient:nonNamespaced
// ManagedProxyConfiguration is the Schema for the managedproxyconfigurations API
type ManagedProxyConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManagedProxyConfigurationSpec   `json:"spec,omitempty"`
	Status ManagedProxyConfigurationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ManagedProxyConfigurationList contains a list of ManagedProxyConfiguration
type ManagedProxyConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagedProxyConfiguration `json:"items"`
}

// +kubebuilder:validation:Enum=SelfSigned;Provided;CertManager
// AuthenticationType defines the source of certificates.
type AuthenticationType string

var (
	SelfSigned AuthenticationType = "SelfSigned"
	//Provided    AuthenticationType = "Provided"
	//CertManager AuthenticationType = "CertManager"
)

type ManagedProxyConfigurationAuthentication struct {
	// +optional
	CertificateSigning ManagedProxyConfigurationCertificateSigning `json:"certificateSigning"`
	// +optional
	CertificateMounting ManagedProxyConfigurationCertificateMounting `json:"certificateMounting"`
}

type ManagedProxyConfigurationCertificateSigning struct {
	// +optional
	// +kubebuilder:default=SelfSigned
	Type AuthenticationType `json:"type"`
	// +optional
	SelfSigned *AuthenticationSelfSigned `json:"selfSigned,omitempty"`
}

type ManagedProxyConfigurationCertificateMounting struct {
	// +optional
	Secrets CertificateSigningSecrets `json:"secrets"`
}

type AuthenticationSelfSigned struct {
	// +optional
	AdditionalSANs []string `json:"additionalSANs,omitempty"`
}

type CertificateSigningRotation struct {
	// +kubebuilder:default=365
	// +optional
	ExpiryDays int `json:"expiryDays"`
	// +kubebuilder:default=200
	// +optional
	ReloadingDays int `json:"reloadingDays"`
}

type CertificateSigningSecrets struct {
	// +kubebuilder:default=proxy-server
	// +optional
	SigningProxyServerSecretName string `json:"signingProxyServerSecretName,omitempty"`
	// +kubebuilder:default=proxy-client
	// +optional
	SigningProxyClientSecretName string `json:"signingProxyClientSecretName,omitempty"`
	// +kubebuilder:default=agent-server
	// +optional
	SigningAgentServerSecretName string `json:"signingAgentServerSecretName,omitempty"`
}

type BootstrapSecret struct {
	// +optional
	Name string `json:"name"`
}

type ManagedProxyConfigurationDeploy struct {
	Ports ManagedProxyConfigurationDeployPorts `json:"ports"`
}

type ManagedProxyConfigurationDeployPorts struct {
	// +optional
	// +kubebuilder:default=8090
	ProxyServer int32 `json:"proxyServer"`
	// +optional
	// +kubebuilder:default=8091
	AgentServer int32 `json:"agentServer"`
	// +optional
	// +kubebuilder:default=8092
	HealthServer int32 `json:"healthServer"`
	// +optional
	// +kubebuilder:default=8095
	AdminServer int32 `json:"adminServer"`
}

type ManagedProxyConfigurationProxyServer struct {
	// +required
	Image string `json:"image"`
	// +optional
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas"`
	// +optional
	// +kubebuilder:default=proxy-entrypoint
	InClusterServiceName string `json:"inClusterServiceName"`
	// +optional
	// +kubebuilder:default=open-cluster-management-cluster-proxy
	Namespace string `json:"namespace"`
	// +optional
	Entrypoint *ManagedProxyConfigurationProxyServerEntrypoint `json:"entrypoint"`
}

type ManagedProxyConfigurationProxyServerEntrypoint struct {
	// +required
	Type EntryPointType `json:"type"`
	// +optional
	LoadBalancerService *EntryPointLoadBalancerService `json:"loadBalancerService"`
	// +optional
	Hostname *EntryPointHostname `json:"hostname"`
}

type EntryPointType string

var (
	EntryPointTypeLoadBalancerService EntryPointType = "LoadBalancerService"
	EntryPointTypeHostname            EntryPointType = "Hostname"
)

type EntryPointLoadBalancerService struct {
	// +optional
	// +kubebuilder:default=proxy-agent-entrypoint
	Name string `json:"name"`
}

type EntryPointHostname struct {
	// +required
	Value string `json:"value"`
}

type ManagedProxyConfigurationProxyAgent struct {
	// +required
	Image string `json:"image"`
	// +optional
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas"`
	// +optional
	ProxyServerHost string `json:"proxyServerHost,omitempty"`
}

const (
	ConditionTypeProxyServerDeployed     = "ProxyServerDeployed"
	ConditionTypeProxyServerSecretSigned = "ProxyServerSecretSigned"
	ConditionTypeAgentServerSecretSigned = "AgentServerSecretSigned"
	ConditionTypeProxyClientSecretSigned = "ProxyClientSecretSigned"
)

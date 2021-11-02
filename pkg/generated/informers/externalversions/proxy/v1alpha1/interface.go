// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "open-cluster-management.io/cluster-proxy/pkg/generated/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// ManagedProxyConfigurations returns a ManagedProxyConfigurationInformer.
	ManagedProxyConfigurations() ManagedProxyConfigurationInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// ManagedProxyConfigurations returns a ManagedProxyConfigurationInformer.
func (v *version) ManagedProxyConfigurations() ManagedProxyConfigurationInformer {
	return &managedProxyConfigurationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

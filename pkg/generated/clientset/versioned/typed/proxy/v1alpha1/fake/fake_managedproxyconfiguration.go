// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1alpha1 "open-cluster-management.io/cluster-proxy/pkg/apis/proxy/v1alpha1"
)

// FakeManagedProxyConfigurations implements ManagedProxyConfigurationInterface
type FakeManagedProxyConfigurations struct {
	Fake *FakeProxyV1alpha1
}

var managedproxyconfigurationsResource = schema.GroupVersionResource{Group: "proxy.open-cluster-management.io", Version: "v1alpha1", Resource: "managedproxyconfigurations"}

var managedproxyconfigurationsKind = schema.GroupVersionKind{Group: "proxy.open-cluster-management.io", Version: "v1alpha1", Kind: "ManagedProxyConfiguration"}

// Get takes name of the managedProxyConfiguration, and returns the corresponding managedProxyConfiguration object, and an error if there is any.
func (c *FakeManagedProxyConfigurations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ManagedProxyConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(managedproxyconfigurationsResource, name), &v1alpha1.ManagedProxyConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ManagedProxyConfiguration), err
}

// List takes label and field selectors, and returns the list of ManagedProxyConfigurations that match those selectors.
func (c *FakeManagedProxyConfigurations) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ManagedProxyConfigurationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(managedproxyconfigurationsResource, managedproxyconfigurationsKind, opts), &v1alpha1.ManagedProxyConfigurationList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.ManagedProxyConfigurationList{ListMeta: obj.(*v1alpha1.ManagedProxyConfigurationList).ListMeta}
	for _, item := range obj.(*v1alpha1.ManagedProxyConfigurationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested managedProxyConfigurations.
func (c *FakeManagedProxyConfigurations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(managedproxyconfigurationsResource, opts))
}

// Create takes the representation of a managedProxyConfiguration and creates it.  Returns the server's representation of the managedProxyConfiguration, and an error, if there is any.
func (c *FakeManagedProxyConfigurations) Create(ctx context.Context, managedProxyConfiguration *v1alpha1.ManagedProxyConfiguration, opts v1.CreateOptions) (result *v1alpha1.ManagedProxyConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(managedproxyconfigurationsResource, managedProxyConfiguration), &v1alpha1.ManagedProxyConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ManagedProxyConfiguration), err
}

// Update takes the representation of a managedProxyConfiguration and updates it. Returns the server's representation of the managedProxyConfiguration, and an error, if there is any.
func (c *FakeManagedProxyConfigurations) Update(ctx context.Context, managedProxyConfiguration *v1alpha1.ManagedProxyConfiguration, opts v1.UpdateOptions) (result *v1alpha1.ManagedProxyConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(managedproxyconfigurationsResource, managedProxyConfiguration), &v1alpha1.ManagedProxyConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ManagedProxyConfiguration), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeManagedProxyConfigurations) UpdateStatus(ctx context.Context, managedProxyConfiguration *v1alpha1.ManagedProxyConfiguration, opts v1.UpdateOptions) (*v1alpha1.ManagedProxyConfiguration, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(managedproxyconfigurationsResource, "status", managedProxyConfiguration), &v1alpha1.ManagedProxyConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ManagedProxyConfiguration), err
}

// Delete takes name of the managedProxyConfiguration and deletes it. Returns an error if one occurs.
func (c *FakeManagedProxyConfigurations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(managedproxyconfigurationsResource, name, opts), &v1alpha1.ManagedProxyConfiguration{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeManagedProxyConfigurations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(managedproxyconfigurationsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.ManagedProxyConfigurationList{})
	return err
}

// Patch applies the patch and returns the patched managedProxyConfiguration.
func (c *FakeManagedProxyConfigurations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ManagedProxyConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(managedproxyconfigurationsResource, name, pt, data, subresources...), &v1alpha1.ManagedProxyConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.ManagedProxyConfiguration), err
}

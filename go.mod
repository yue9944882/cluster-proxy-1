module open-cluster-management.io/cluster-proxy

go 1.16

require (
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.14.0
	github.com/openshift/library-go v0.0.0-20210916194400-ae21aab32431
	github.com/pkg/errors v0.9.1
	k8s.io/api v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
	k8s.io/klog/v2 v2.9.0
	open-cluster-management.io/addon-framework v0.0.0-20211101093604-8c0b8f52ad78
	open-cluster-management.io/api v0.0.0-20210916013819-2e58cdb938f9
	sigs.k8s.io/controller-runtime v0.9.5
)

replace (
	k8s.io/api v0.21.1 => k8s.io/api v0.20.2
	k8s.io/apimachinery v0.21.1 => k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.21.1 => k8s.io/client-go v0.20.2
)

module open-cluster-management.io/cluster-proxy

go 1.16

require (
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/pkg/errors v0.9.1
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/klog/v2 v2.8.0
	open-cluster-management.io/addon-framework v0.0.0-20210803032803-58eac513499e
	open-cluster-management.io/api v0.0.0-20210823013037-9667ae902e4b
	sigs.k8s.io/controller-runtime v0.8.3
)

replace (
	k8s.io/api v0.21.1 => k8s.io/api v0.20.2
	k8s.io/apimachinery v0.21.1 => k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.21.1 => k8s.io/client-go v0.20.2
)

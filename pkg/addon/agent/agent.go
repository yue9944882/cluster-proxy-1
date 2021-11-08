package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"open-cluster-management.io/cluster-proxy/pkg/addon/operator/authentication/selfsigned"
	proxyv1alpha1 "open-cluster-management.io/cluster-proxy/pkg/apis/proxy/v1alpha1"
	"open-cluster-management.io/cluster-proxy/pkg/common"

	"open-cluster-management.io/addon-framework/pkg/agent"
	addonv1alpha1 "open-cluster-management.io/api/addon/v1alpha1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	"open-cluster-management.io/cluster-proxy/pkg/config"

	appsv1 "k8s.io/api/apps/v1"
	csrv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	applyrbacv1 "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ agent.AgentAddon = &proxyAgent{}

const (
	ProxyAgentSignerName = "open-cluster-management.io/proxy-agent-signer"
)

func NewProxyAgent(runtimeClient client.Client, nativeClient kubernetes.Interface, signer selfsigned.SelfSigner) agent.AgentAddon {
	return &proxyAgent{
		runtimeClient: runtimeClient,
		nativeClient:  nativeClient,
		selfSigner:    signer,
	}
}

type proxyAgent struct {
	runtimeClient client.Reader
	nativeClient  kubernetes.Interface
	selfSigner    selfsigned.SelfSigner
}

func (p *proxyAgent) Manifests(managedCluster *clusterv1.ManagedCluster, addon *addonv1alpha1.ManagedClusterAddOn) ([]runtime.Object, error) {
	clusterAddon := &addonv1alpha1.ClusterManagementAddOn{}
	if err := p.runtimeClient.Get(context.TODO(), types.NamespacedName{
		Name: addon.Name,
	}, clusterAddon); err != nil {
		return nil, err
	}
	config := &proxyv1alpha1.ManagedProxyConfiguration{}
	if err := p.runtimeClient.Get(context.TODO(), types.NamespacedName{
		Name: clusterAddon.Spec.AddOnConfiguration.CRName,
	}, config); err != nil {
		return nil, err
	}
	lbEndpoint := ""
	if config.Spec.ProxyServer.Entrypoint.Type == proxyv1alpha1.EntryPointTypeLoadBalancerService {
		if entrySvc, err := p.nativeClient.CoreV1().
			Services(config.Spec.ProxyServer.Namespace).
			Get(context.TODO(), config.Spec.ProxyServer.Entrypoint.LoadBalancerService.Name, metav1.GetOptions{}); err == nil {
			if len(entrySvc.Status.LoadBalancer.Ingress) > 0 {
				lbEndpoint = entrySvc.Status.LoadBalancer.Ingress[0].IP
			}
		}
	}
	deploying := []runtime.Object{
		newCASecret(addon.Spec.InstallNamespace, AgentCASecretName, p.selfSigner.CAData()),
		newClusterService(addon.Spec.InstallNamespace, managedCluster.Name),
		newAgentDeployment(managedCluster.Name, addon.Spec.InstallNamespace, config, lbEndpoint),
	}
	return deploying, nil
}

func (p *proxyAgent) GetAgentAddonOptions() agent.AgentAddonOptions {
	return agent.AgentAddonOptions{
		AddonName: common.AddonName,
		Registration: &agent.RegistrationOption{
			CSRConfigurations: func(cluster *clusterv1.ManagedCluster) []addonv1alpha1.RegistrationConfig {
				return []addonv1alpha1.RegistrationConfig{
					{
						SignerName: ProxyAgentSignerName,
						Subject: addonv1alpha1.Subject{
							User: common.SubjectUserClusterProxyAgent,
							Groups: []string{
								common.SubjectGroupClusterProxy,
							},
						},
					},
					{
						SignerName: csrv1.KubeAPIServerClientSignerName,
						Subject: addonv1alpha1.Subject{
							User: common.SubjectUserClusterAddonAgent,
							Groups: []string{
								common.SubjectGroupClusterProxy,
							},
						},
					},
				}
			},
			CSRApproveCheck: func(cluster *clusterv1.ManagedCluster, addon *addonv1alpha1.ManagedClusterAddOn, csr *csrv1.CertificateSigningRequest) bool {
				return cluster.Spec.HubAcceptsClient
			},
			PermissionConfig: p.setupPermission,
			CSRSign: func(csr *csrv1.CertificateSigningRequest) []byte {
				if csr.Spec.SignerName != ProxyAgentSignerName {
					return nil
				}
				b, _ := pem.Decode(csr.Spec.Request)
				parsed, err := x509.ParseCertificateRequest(b.Bytes)
				if err != nil {
					return nil
				}
				validity := time.Hour * 24 * 180
				caCert := p.selfSigner.CA().Config.Certs[0]
				tmpl := &x509.Certificate{
					SerialNumber:       caCert.SerialNumber,
					Subject:            parsed.Subject,
					DNSNames:           parsed.DNSNames,
					IPAddresses:        parsed.IPAddresses,
					EmailAddresses:     parsed.EmailAddresses,
					URIs:               parsed.URIs,
					PublicKeyAlgorithm: parsed.PublicKeyAlgorithm,
					PublicKey:          parsed.PublicKey,
					Extensions:         parsed.Extensions,
					ExtraExtensions:    parsed.ExtraExtensions,
					IsCA:               false,
					KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
					ExtKeyUsage: []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
						x509.ExtKeyUsageClientAuth,
					},
				}
				now := time.Now()
				tmpl.NotBefore = now
				tmpl.NotAfter = now.Add(validity)

				rsaKey := p.selfSigner.CA().Config.Key.(*rsa.PrivateKey)
				der, err := x509.CreateCertificate(
					rand.Reader,
					tmpl,
					p.selfSigner.CA().Config.Certs[0],
					parsed.PublicKey,
					rsaKey)
				if err != nil {
					return nil
				}
				return pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: der,
				})
			},
		},
	}
}

func (p *proxyAgent) setupPermission(cluster *clusterv1.ManagedCluster, addon *addonv1alpha1.ManagedClusterAddOn) error {
	namespace := cluster.Name

	role := applyrbacv1.Role("cluster-proxy-addon-agent", namespace).
		WithRules(applyrbacv1.PolicyRule().
			WithAPIGroups("coordination.k8s.io").
			WithVerbs("*").
			WithResources("leases"))
	if _, err := p.nativeClient.RbacV1().
		Roles(namespace).
		Apply(
			context.TODO(),
			role,
			metav1.ApplyOptions{
				FieldManager: "addon-manager",
			}); err != nil {
		return err
	}

	rolebinding := applyrbacv1.RoleBinding("cluster-proxy-addon-agent", namespace).
		WithRoleRef(applyrbacv1.RoleRef().
			WithKind("Role").
			WithName("cluster-proxy-addon-agent")).
		WithSubjects(applyrbacv1.Subject().
			WithKind(rbacv1.GroupKind).
			WithName(common.SubjectGroupClusterProxy))
	if _, err := p.nativeClient.RbacV1().
		RoleBindings(namespace).
		Apply(
			context.TODO(),
			rolebinding,
			metav1.ApplyOptions{
				FieldManager: "addon-manager",
			}); err != nil {
		return err
	}
	return nil
}

const (
	ApiserverNetworkProxyLabelAddon     = "open-cluster-management.io/addon"
	ApiserverNetworkProxyLabelComponent = "open-cluster-management.io/component"

	AgentSecretName   = "cluster-proxy-open-cluster-management.io-proxy-agent-signer-client-cert"
	AgentCASecretName = "cluster-proxy-ca"
)

func newAgentDeployment(clusterName, targetNamespace string, proxyConfig *proxyv1alpha1.ManagedProxyConfiguration, loadBalancerEndpoint string) *appsv1.Deployment {
	serviceEntryPoint := proxyConfig.Spec.ProxyServer.InClusterServiceName + "." + proxyConfig.Spec.ProxyServer.Namespace
	if len(proxyConfig.Spec.ProxyAgent.ProxyServerHost) > 0 {
		serviceEntryPoint = proxyConfig.Spec.ProxyAgent.ProxyServerHost
	} else if len(loadBalancerEndpoint) > 0 {
		serviceEntryPoint = loadBalancerEndpoint
	}
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      proxyConfig.Name + "-" + common.ComponentNameProxyAgent,
			Namespace: targetNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &proxyConfig.Spec.ProxyAgent.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					ApiserverNetworkProxyLabelAddon:     common.AddonName,
					ApiserverNetworkProxyLabelComponent: common.ComponentNameProxyAgent,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						ApiserverNetworkProxyLabelAddon:     common.AddonName,
						ApiserverNetworkProxyLabelComponent: common.ComponentNameProxyAgent,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  common.ComponentNameProxyAgent,
							Image: proxyConfig.Spec.ProxyAgent.Image,
							Args: []string{
								"--proxy-server-host=" + serviceEntryPoint,
								"--agent-identifiers=" +
									"host=" + clusterName + "&" +
									"host=" + clusterName + "." + targetNamespace + "&" +
									"host=" + clusterName + "." + targetNamespace + ".svc.cluster.local",
								"--ca-cert=/etc/ca/ca.crt",
								"--agent-cert=/etc/tls/tls.crt",
								"--agent-key=/etc/tls/tls.key",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "ca",
									ReadOnly:  true,
									MountPath: "/etc/ca/",
								},
								{
									Name:      "hub",
									ReadOnly:  true,
									MountPath: "/etc/tls/",
								},
							},
						},
						{
							Name:  "addon-agent",
							Image: config.AgentImageName,
							Args: []string{
								"--hub-kubeconfig=/etc/kubeconfig/kubeconfig",
								"--cluster-name=" + clusterName,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "hub-kubeconfig",
									ReadOnly:  true,
									MountPath: "/etc/kubeconfig/",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "ca",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: AgentCASecretName,
								},
							},
						},
						{
							Name: "hub",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: AgentSecretName,
								},
							},
						},
						{
							Name: "hub-kubeconfig",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "cluster-proxy-hub-kubeconfig",
								},
							},
						},
					},
				},
			},
		},
	}
}

func newCASecret(namespace, name string, caData []byte) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: map[string][]byte{
			selfsigned.TLSCACert: caData,
		},
	}
}

func newClusterService(namespace, name string) *corev1.Service {
	const nativeKubernetesInClusterService = "kubernetes.default.svc.cluster.local"
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: nativeKubernetesInClusterService,
		},
	}
}

package agent

import (
	"context"
	"open-cluster-management.io/cluster-proxy/pkg/operator/hub/authentication"

	"open-cluster-management.io/addon-framework/pkg/agent"
	addonv1alpha1 "open-cluster-management.io/api/addon/v1alpha1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	proxyv1alpha1 "open-cluster-management.io/cluster-proxy/api/v1alpha1"
	"open-cluster-management.io/cluster-proxy/pkg/addon/common"

	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	csrv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ agent.AgentAddon = &proxyAgent{}

func NewProxyAgent(runtimeClient client.Client, nativeClient kubernetes.Interface) agent.AgentAddon {
	return &proxyAgent{
		runtimeClient: runtimeClient,
		nativeClient:  nativeClient,
	}
}

type proxyAgent struct {
	runtimeClient client.Reader
	nativeClient  kubernetes.Interface
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

	secret, err := newAgentSecrets(p.nativeClient, config, addon.Spec.InstallNamespace)
	if err != nil {
		return nil, err
	}
	deploying := []runtime.Object{
		secret,
		newAgentDeployment(managedCluster.Name, addon.Spec.InstallNamespace, config),
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
						SignerName: csrv1.KubeAPIServerClientSignerName,
						Subject: addonv1alpha1.Subject{
							User: common.SubjectUserClusterProxyAgent,
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
			PermissionConfig: func(cluster *clusterv1.ManagedCluster, addon *addonv1alpha1.ManagedClusterAddOn) error {
				return nil
			},
		},
	}
}

const (
	ApiserverNetworkProxyLabelAddon     = "open-cluster-management.io/addon"
	ApiserverNetworkProxyLabelComponent = "open-cluster-management.io/component"
)

func newAgentSecrets(k kubernetes.Interface, config *proxyv1alpha1.ManagedProxyConfiguration, targetNamespace string) (*corev1.Secret, error) {
	namespace := config.Spec.Authentication.AgentAuth.ServiceAccountNamespace
	name := config.Spec.Authentication.AgentAuth.ServiceAccountName
	tr := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences: []string{
				config.Spec.Authentication.AgentAuth.ServiceAccountAudience,
			},
		},
	}
	proxyServerCert, err := k.CoreV1().
		Secrets(config.Spec.ProxyServer.Namespace).
		Get(context.TODO(), config.Spec.Authentication.CertificateMounting.Secrets.SigningProxyServerSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	createdTr, err := k.CoreV1().
		ServiceAccounts(namespace).
		CreateToken(context.TODO(), name, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	agentClientSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: targetNamespace,
			Name:      name,
		},
		Data: map[string][]byte{
			authentication.TLSCACert: proxyServerCert.Data[authentication.TLSCACert],
			"token":                  []byte(createdTr.Status.Token),
		},
	}

	created, err := k.CoreV1().
		Secrets(targetNamespace).
		Create(context.TODO(), agentClientSecret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return agentClientSecret, nil
		}
		return nil, err
	}
	return created, nil
}

func newAgentDeployment(clusterName, targetNamespace string, proxyConfig *proxyv1alpha1.ManagedProxyConfiguration) *appsv1.Deployment {
	serviceEntryPoint := proxyConfig.Spec.ProxyServer.InClusterServiceName + "." + proxyConfig.Spec.ProxyServer.Namespace
	if len(proxyConfig.Spec.ProxyAgent.ProxyServerHost) > 0 {
		serviceEntryPoint = proxyConfig.Spec.ProxyAgent.ProxyServerHost
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
								"--agent-identifiers=host=" + clusterName,
								"--ca-cert=/etc/agent-auth/ca.crt",
								"--service-account-token-path=/etc/agent-auth/token",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "agent-auth",
									ReadOnly:  true,
									MountPath: "/etc/agent-auth/",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "agent-auth",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: proxyConfig.Spec.Authentication.AgentAuth.ServiceAccountName,
								},
							},
						},
					},
				},
			},
		},
	}
}

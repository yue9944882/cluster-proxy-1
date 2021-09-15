package controllers

import (
	"context"
	"crypto/x509"
	"net"
	"strconv"
	"time"

	addonv1alpha1 "open-cluster-management.io/api/addon/v1alpha1"
	proxyv1alpha1 "open-cluster-management.io/cluster-proxy/api/v1alpha1"
	"open-cluster-management.io/cluster-proxy/pkg/addon/common"
	"open-cluster-management.io/cluster-proxy/pkg/addon/hub"
	"open-cluster-management.io/cluster-proxy/pkg/operator/hub/authentication"

	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/cert"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var _ reconcile.Reconciler = &ClusterManagementAddonReconciler{}
var log = ctrl.Log.WithName("ClusterManagementAddonReconciler")

type ClusterManagementAddonReconciler struct {
	client.Client
}

func (c *ClusterManagementAddonReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	// get the latest cluster-addon
	addon := &addonv1alpha1.ClusterManagementAddOn{}
	if err := c.Client.Get(ctx, request.NamespacedName, addon); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Cannot find cluster-addon", "name", request.Name)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if len(addon.Spec.AddOnConfiguration.CRName) == 0 {
		log.Info("Skipping cluster-addon, no config coordinate", "name", request.Name)
		return reconcile.Result{}, nil
	}
	// get the related proxy configuration
	config := &proxyv1alpha1.ManagedProxyConfiguration{}
	if err := c.Client.Get(ctx, types.NamespacedName{
		Name: addon.Spec.AddOnConfiguration.CRName,
	}, config); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Cannot find proxy-configuration", "name", addon.Spec.AddOnConfiguration.CRName)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	err := c.ensureNamespace(config)
	if err != nil {
		return reconcile.Result{}, err
	}
	secretDumped, err := c.signIfNotPresent(config)
	if err != nil {
		return reconcile.Result{}, err
	}
	_, err = c.setupPermission(config)
	if err != nil {
		return reconcile.Result{}, err
	}
	deployed, err := c.deployProxyServer(config)
	if err != nil {
		return reconcile.Result{}, err
	}

	// refreshing status
	if err := c.refreshStatus(config, deployed, secretDumped); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (c *ClusterManagementAddonReconciler) SetupWithManager(mgr ctrl.Manager) error {
	c.Client = mgr.GetClient()
	return ctrl.NewControllerManagedBy(mgr).
		For(&addonv1alpha1.ClusterManagementAddOn{}).
		Watches(
			&source.Kind{
				Type: &proxyv1alpha1.ManagedProxyConfiguration{},
			},
			&hub.ManagedProxyConfigurationHandler{
				Client: c,
			}).
		Complete(c)
}

func (c *ClusterManagementAddonReconciler) signIfNotPresent(config *proxyv1alpha1.ManagedProxyConfiguration) (bool, error) {
	// all secrets present
	secretsPresent, err := c.areSecretsAllPresent(context.TODO(), config)
	if err != nil {
		log.Error(err, "Failed to check if expected secrets are present", "name", config.Name)
		return false, err
	}
	if secretsPresent {
		return true, nil
	}
	secretDumped := false
	if !secretsPresent {
		// sign certificate
		switch config.Spec.Authentication.CertificateSigning.Type {
		// TODO: support more certificate providers
		case proxyv1alpha1.SelfSigned:
			err := c.selfSignCertificates(config)
			if err != nil {
				return false, err
			}
			secretDumped = true
		}
	}
	return secretDumped, nil
}

func (c *ClusterManagementAddonReconciler) areSecretsAllPresent(
	ctx context.Context,
	config *proxyv1alpha1.ManagedProxyConfiguration,
) (bool, error) {

	for _, target := range []types.NamespacedName{
		{
			Namespace: config.Spec.ProxyServer.Namespace,
			Name:      config.Spec.Authentication.CertificateMounting.Secrets.SigningProxyServerSecretName,
		},
		{
			Namespace: config.Spec.ProxyServer.Namespace,
			Name:      config.Spec.Authentication.CertificateMounting.Secrets.SigningAgentServerSecretName,
		},
		{
			Namespace: config.Spec.ProxyServer.Namespace,
			Name:      config.Spec.Authentication.CertificateMounting.Secrets.SigningProxyClientSecretName,
		},
	} {
		if err := c.Client.Get(ctx, target, &corev1.Secret{}); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

func (c *ClusterManagementAddonReconciler) selfSignCertificates(
	config *proxyv1alpha1.ManagedProxyConfiguration,
) error {

	// issuing csr objects
	selfSigner, err := authentication.NewSelfSigner()
	if err != nil {
		return err
	}

	secretNamespace := config.Spec.ProxyServer.Namespace
	targets := []struct {
		componentName string
		secretName    string
		usages        []x509.ExtKeyUsage
	}{
		{
			componentName: common.ComponentNameProxyServer,
			secretName:    config.Spec.Authentication.CertificateMounting.Secrets.SigningProxyServerSecretName,
			usages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
		},
		{
			componentName: common.ComponentNameProxyClient,
			secretName:    config.Spec.Authentication.CertificateMounting.Secrets.SigningProxyClientSecretName,
			usages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
		},
		{
			componentName: common.ComponentNameProxyAgentServer,
			secretName:    config.Spec.Authentication.CertificateMounting.Secrets.SigningAgentServerSecretName,
			usages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
		},
	}

	for _, target := range targets {
		cfg := cert.Config{
			CommonName: target.componentName,
			Organization: []string{
				common.SubjectGroupClusterProxy,
			},
			AltNames: cert.AltNames{},
			Usages:   target.usages,
		}
		if containsUsage(target.usages, x509.ExtKeyUsageServerAuth) {
			for _, san := range config.Spec.Authentication.CertificateSigning.SelfSigned.AdditionalSANs {
				if ip := net.ParseIP(san); ip != nil {
					cfg.AltNames.IPs = append(cfg.AltNames.IPs, ip)
				} else {
					cfg.AltNames.DNSNames = append(cfg.AltNames.DNSNames, san)
				}
			}
			cfg.AltNames.DNSNames = append(cfg.AltNames.DNSNames,
				config.Spec.ProxyServer.InClusterServiceName+"."+config.Spec.ProxyServer.Namespace,
				config.Spec.ProxyServer.InClusterServiceName+"."+config.Spec.ProxyServer.Namespace+".svc",
			)
		}
		pair, err := selfSigner.Sign(
			cfg,
			time.Duration(config.Spec.Authentication.CertificateSigning.SelfSigned.Rotation.ExpiryDays)*time.Hour*24)
		if err != nil {
			return errors.Wrapf(err, "failed signing certificates")
		}
		certData, keyData, err := pair.AsBytes()
		if err != nil {
			return errors.Wrapf(err, "failed signing certificates")
		}
		if err := authentication.DumpSecret(
			c.Client,
			secretNamespace,
			target.secretName,
			selfSigner.CAData(),
			certData,
			keyData,
		); err != nil {
			return errors.Wrapf(err, "failed dumping signed certificates")
		}
	}
	return nil
}

func (c *ClusterManagementAddonReconciler) refreshStatus(config *proxyv1alpha1.ManagedProxyConfiguration, deployed, secretDumped bool) error {
	status := proxyv1alpha1.ManagedProxyConfigurationStatus{}
	status.LastObservedGeneration = config.Generation
	status.Conditions = c.getConditions(deployed, secretDumped)
	mungedStatus := config.Status.DeepCopy()
	for i := range mungedStatus.Conditions {
		mungedStatus.Conditions[i].LastTransitionTime = metav1.Time{}
	}
	if equality.Semantic.DeepEqual(&status, mungedStatus) {
		return nil
	}
	now := metav1.Now()
	editingConfig := config.DeepCopy()
	editingConfig.Status = status
	for i := range editingConfig.Status.Conditions {
		editingConfig.Status.Conditions[i].LastTransitionTime = now
	}
	return c.Client.Status().Update(context.TODO(), editingConfig)
}

func (c *ClusterManagementAddonReconciler) ensureNamespace(config *proxyv1alpha1.ManagedProxyConfiguration) error {
	if err := c.Client.Get(context.TODO(), types.NamespacedName{
		Name: config.Spec.ProxyServer.Namespace,
	}, &corev1.Namespace{}); err != nil {
		if apierrors.IsNotFound(err) {
			if err := c.Client.Create(context.TODO(), &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: config.Spec.ProxyServer.Namespace,
				},
			}); err != nil {
				return errors.Wrapf(err, "failed creating namespace %q on absence", config.Spec.ProxyServer.Namespace)
			}
			return nil
		}
		return errors.Wrapf(err, "failed check namespace %q's presence", config.Spec.ProxyServer.Namespace)
	}
	return nil
}

func (c *ClusterManagementAddonReconciler) setupPermission(config *proxyv1alpha1.ManagedProxyConfiguration) (bool, error) {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "open-cluster-management:addon:cluster-proxy:agent-auth",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs: []string{
					"create",
				},
				APIGroups: []string{
					"authentication.k8s.io",
				},
				Resources: []string{
					"tokenreviews",
				},
			},
		},
	}
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "open-cluster-management:addon:cluster-proxy:agent-auth",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "open-cluster-management:addon:cluster-proxy:agent-auth",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Namespace: config.Spec.ProxyServer.Namespace,
				Name:      config.Spec.Authentication.AgentAuth.ServiceAccountName,
			},
		},
	}
	if err := c.Client.Create(context.TODO(), clusterRole); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return false, err
		}
	}
	if err := c.Client.Create(context.TODO(), clusterRoleBinding); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return false, err
		}
	}
	return true, nil
}

func (c *ClusterManagementAddonReconciler) deployProxyServer(config *proxyv1alpha1.ManagedProxyConfiguration) (bool, error) {
	agentAuthServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.Spec.ProxyServer.Namespace,
			Name:      config.Spec.Authentication.AgentAuth.ServiceAccountName,
		},
	}
	proxyService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.Spec.ProxyServer.Namespace,
			Name:      config.Spec.ProxyServer.InClusterServiceName,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				common.LabelKeyComponentName: common.ComponentNameProxyServer,
			},
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name: "proxy-server",
					Port: 8090,
				},
				{
					Name: "agent-server",
					Port: 8091,
				},
			},
		},
	}
	proxyServerDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.Spec.ProxyServer.Namespace,
			Name:      config.Name,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &config.Spec.ProxyServer.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					common.LabelKeyComponentName: common.ComponentNameProxyServer,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						common.LabelKeyComponentName: common.ComponentNameProxyServer,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: agentAuthServiceAccount.Name,
					Containers: []corev1.Container{
						{
							Name:  common.ComponentNameProxyServer,
							Image: config.Spec.ProxyServer.Image,
							Args: []string{
								"--server-count=" + strconv.Itoa(int(config.Spec.ProxyServer.Replicas)),
								"--agent-namespace=" + config.Spec.Authentication.AgentAuth.ServiceAccountNamespace,
								"--agent-service-account=" + config.Spec.Authentication.AgentAuth.ServiceAccountName,
								"--authentication-audience=" + config.Spec.Authentication.AgentAuth.ServiceAccountAudience,
								"--proxy-strategies=destHost",
								"--server-ca-cert=/etc/server-pki/ca.crt",
								"--server-cert=/etc/server-pki/tls.crt",
								"--server-key=/etc/server-pki/tls.key",
								"--cluster-cert=/etc/agent-pki/tls.crt",
								"--cluster-key=/etc/agent-pki/tls.key",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "proxy-server-certs",
									ReadOnly:  true,
									MountPath: "/etc/server-pki/",
								},
								{
									Name:      "proxy-agent-certs",
									ReadOnly:  true,
									MountPath: "/etc/agent-pki/",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "proxy-server-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: config.Spec.Authentication.CertificateMounting.Secrets.SigningProxyServerSecretName,
								},
							},
						},
						{
							Name: "proxy-agent-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: config.Spec.Authentication.CertificateMounting.Secrets.SigningAgentServerSecretName,
								},
							},
						},
					},
				},
			},
		},
	}
	if err := c.Client.Create(context.TODO(), agentAuthServiceAccount); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return false, err
		}
	}
	if err := c.Client.Create(context.TODO(), proxyService); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return false, err
		}
	}
	if err := c.Client.Create(context.TODO(), proxyServerDeployment); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return false, err
		}
	}

	return true, nil
}

func (c *ClusterManagementAddonReconciler) getConditions(deployed, secretDumped bool) []metav1.Condition {
	secretDumpedCondition := metav1.Condition{
		Type:   proxyv1alpha1.ConditionTypeAllSecretGenerated,
		Status: metav1.ConditionFalse,
		Reason: "Generated",
	}
	if secretDumped {
		secretDumpedCondition.Status = metav1.ConditionTrue
	}
	deployedCondition := metav1.Condition{
		Type:   proxyv1alpha1.ConditionTypeProxyServerDeployed,
		Status: metav1.ConditionFalse,
		Reason: "Deployed",
	}
	if deployed {
		deployedCondition.Status = metav1.ConditionTrue
	}

	return []metav1.Condition{
		deployedCondition,
		secretDumpedCondition,
	}
}

func containsUsage(usages []x509.ExtKeyUsage, u x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if u == usage {
			return true
		}
	}
	return false
}

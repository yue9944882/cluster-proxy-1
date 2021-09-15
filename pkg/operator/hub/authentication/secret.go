package authentication

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	TLSCACert = "ca.crt"
)

func DumpSecret(c client.Client, namespace, name string, caData, certData, keyData []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certData,
			corev1.TLSPrivateKeyKey: keyData,
			TLSCACert:               caData,
		},
	}
	return c.Create(context.TODO(), secret)
}

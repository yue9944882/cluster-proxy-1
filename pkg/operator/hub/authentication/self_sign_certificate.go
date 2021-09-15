package authentication

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"open-cluster-management.io/cluster-proxy/pkg/addon/common"

	"k8s.io/client-go/util/cert"
)

var (
	rsaKeySize = 2048 // a decent number, as of 2019
	bigOne     = big.NewInt(1)
)

type SelfSigner interface {
	Sign(cfg cert.Config, expiry time.Duration) (CertPair, error)
	CAData() []byte
}

var _ SelfSigner = &selfSigner{}

type selfSigner struct {
	caCert     *x509.Certificate
	caKey      crypto.Signer
	nextSerial *big.Int
}

func NewSelfSigner() (SelfSigner, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, err
	}
	caCert, err := cert.NewSelfSignedCACert(cert.Config{
		CommonName: common.AddonFullName,
	}, privateKey)
	if err != nil {
		return nil, err
	}
	return &selfSigner{
		caCert:     caCert,
		caKey:      privateKey,
		nextSerial: big.NewInt(1),
	}, nil
}

func (s selfSigner) Sign(cfg cert.Config, expiry time.Duration) (CertPair, error) {
	now := time.Now()

	key, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return CertPair{}, fmt.Errorf("unable to create private key: %v", err)
	}

	serial := new(big.Int).Set(s.nextSerial)
	s.nextSerial.Add(s.nextSerial, bigOne)

	template := x509.Certificate{
		Subject:      pkix.Name{CommonName: cfg.CommonName, Organization: cfg.Organization},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  cfg.Usages,
		NotBefore:    now.UTC(),
		NotAfter:     now.Add(expiry).UTC(),
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, key.Public(), s.caKey)
	if err != nil {
		return CertPair{}, fmt.Errorf("unable to create certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return CertPair{}, fmt.Errorf("generated invalid certificate, could not parse: %v", err)
	}

	return CertPair{
		Key:  key,
		Cert: certificate,
	}, nil
}

func (s selfSigner) CAData() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.caCert.Raw,
	})
}

type CertPair struct {
	Key  crypto.Signer
	Cert *x509.Certificate
}

func (k CertPair) CertBytes() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: k.Cert.Raw,
	})
}

func (k CertPair) AsBytes() (cert []byte, key []byte, err error) {
	cert = k.CertBytes()

	rawKeyData, err := x509.MarshalPKCS8PrivateKey(k.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode private key: %v", err)
	}

	key = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: rawKeyData,
	})

	return cert, key, nil
}

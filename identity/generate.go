package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

func Generate(profile Profile) (*Identity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		
	}

	temp := &x509.Certificate{
		Version: 1,
		SerialNumber: big.NewInt(1),
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(30 * 24 * 60 * time.Second),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, temp, temp, publicKey, privateKey)
	if err != nil {

	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {

	}
	id := &Identity{
		Certificate: cert,
		PrivateKey: privateKey,
	}
	return id, nil
}
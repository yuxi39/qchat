package identity

import (
	"crypto/ed25519"
	"crypto/x509"
)

type IdentityType int

const (
	IdentityCA IdentityType = iota
	IdentityServer
	IdentityClient
)

type Identity struct {
	ID          string
	Certificate *x509.Certificate
	PrivateKey  ed25519.PrivateKey
}

package tormessage

import (
	"crypto/rsa"
	"io"
)

type RSA interface {
	GenerateRSAKey(io.Reader) (*rsa.PrivateKey, *rsa.PublicKey, error)
}

type rsaTools struct {
	RSA
}

func NewRSA() RSA {
	return &rsaTools{}
}

func (e *rsaTools) GenerateRSAKey(rand io.Reader) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

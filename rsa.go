package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

type rsaTools struct {
	RSA
}

func NewRSA() RSA {
	return &rsaTools{}
}

func (e *rsaTools) GenerateKey(rand io.Reader) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func (e *rsaTools) SignMessage(rand io.Reader, privateKey rsa.PrivateKey, message Message) (*Message, error) {
	h := sha256.New()
	h.Write(message.Message)
	d := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand, &privateKey, crypto.SHA256, d)
	if err != nil {
		return nil, err
	}
	message.Signature = signature
	return &message, nil
}

func (e *rsaTools) VerifyMessage(rand io.Reader, publicKey rsa.PublicKey, message Message) error {
	h := sha256.New()
	h.Write(message.Message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, d, message.Signature)
}

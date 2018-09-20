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

func (e *rsaTools) GenerateRSAKey(rand io.Reader) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func (e *rsaTools) SignMessage(rand io.Reader, privateKey rsa.PrivateKey, message MessageEncrypted) (*MessageEncrypted, error) {
	messageHasher := sha256.New()
	messageHasher.Write(message.Message)
	messageHash := messageHasher.Sum(nil)

	headerHasher := sha256.New()
	headerHasher.Write(message.Header)
	headerHash := headerHasher.Sum(nil)

	messageSignature, err := rsa.SignPKCS1v15(rand, &privateKey, crypto.SHA256, messageHash)
	if err != nil {
		return nil, err
	}

	headerSignature, err := rsa.SignPKCS1v15(rand, &privateKey, crypto.SHA256, headerHash)
	if err != nil {
		return nil, err
	}

	message.MessageSignature = messageSignature
	message.HeaderSignature = headerSignature
	return &message, nil
}

func (e *rsaTools) VerifyMessage(rand io.Reader, publicKey rsa.PublicKey, message MessageEncrypted) error {
	messageHasher := sha256.New()
	messageHasher.Write(message.Message)
	messageHash := messageHasher.Sum(nil)

	headerHasher := sha256.New()
	headerHasher.Write(message.Header)
	headerHash := headerHasher.Sum(nil)
	err := rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, messageHash, message.MessageSignature)
	if err != nil {
		return err
	}
	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, headerHash, message.HeaderSignature)
	if err != nil {
		return err
	}
	return nil
}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

type aesTools struct {
	AES
}

func NewAES() AES {
	return &aesTools{}
}

func (e *aesTools) Encrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}

func (e *aesTools) Decrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (e *aesTools) GenerateAESKey(rand io.Reader) ([]byte, error) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (e *aesTools) GenerateAESNonce(rand io.Reader) ([]byte, error) {
	nonce := make([]byte, 12)
	_, err := io.ReadFull(rand, nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

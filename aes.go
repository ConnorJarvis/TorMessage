package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/gob"
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

func (e *aesTools) EncryptHeader(header Header, key []byte, nonce []byte) ([]byte, error) {
	bytes := bytes.Buffer{}
	encoder := gob.NewEncoder(&bytes)
	err := encoder.Encode(header)
	if err != nil {
		return nil, err
	}
	ciphertext, err := e.Encrypt(bytes.Bytes(), key, nonce)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil

}

func (e *aesTools) DecryptHeader(data []byte, key []byte, nonce []byte) (*Header, error) {

	plaintext, err := e.Decrypt(data, key, nonce)
	if err != nil {
		return nil, err
	}

	header := Header{}
	initalBytes := bytes.Buffer{}
	initalBytes.Write([]byte(plaintext))

	decoder := gob.NewDecoder(&initalBytes)
	err = decoder.Decode(&header)
	if err != nil {
		return nil, err
	}

	return &header, nil
}

func (e *aesTools) EncryptMessage(message interface{}, key []byte, nonce []byte) ([]byte, error) {
	bytes := bytes.Buffer{}
	encoder := gob.NewEncoder(&bytes)
	err := encoder.Encode(message)
	if err != nil {
		return nil, err
	}
	ciphertext, err := e.Encrypt(bytes.Bytes(), key, nonce)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil

}

func (e *aesTools) DecryptMessage(data []byte, key []byte, nonce []byte, messageType int) (interface{}, error) {

	plaintext, err := e.Decrypt(data, key, nonce)
	if err != nil {
		return nil, err
	}
	initalBytes := bytes.Buffer{}
	initalBytes.Write([]byte(plaintext))
	decoder := gob.NewDecoder(&initalBytes)

	if messageType == 1 {
		message := InitialMessage{}
		err = decoder.Decode(&message)
		if err != nil {
			return nil, err
		}
		return &message, nil
	} else if messageType == 2 {
		message := NegotiateKeysMessage{}
		err = decoder.Decode(&message)
		if err != nil {
			return nil, err
		}
		return &message, nil
	} else if messageType == 3 {
		message := TextMessage{}
		err = decoder.Decode(&message)
		if err != nil {
			return nil, err
		}
		return &message, nil
	}

	return nil, nil
}
